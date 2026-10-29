// Package admin は mtls-ca の管理画面（Web 画面）を提供する。
//
//   - ACME とは別のポートで待ち受ける（localhost か管理用のサブネットのアドレスで待ち受ける前提）
//   - ログインはこの CA が発行したクライアント証明書による mTLS。パスワードは使わない。
//     入れる管理者は設定の admin.allowed_clients（証明書の名前のパターン）で限る
//   - アクセスはすべて監査ログ（category=audit）に残す
//   - 状態の概要、発行済み証明書、EAB 鍵、ログを閲覧できる。秘密情報（鍵・HMAC）は表示しない
//     （例外として、EAB 鍵を発行した直後の画面にだけ、その HMAC 鍵を一度表示する）
//   - admin.operators に一致する管理者だけが、EAB 鍵の発行・取り消しと証明書の失効を行える（actions.go）
package admin

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/eab"
	"github.com/nobumin/mtls_manager/internal/federation"
	"github.com/nobumin/mtls_manager/internal/logbuf"
	"github.com/nobumin/mtls_manager/internal/names"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/store"
	"github.com/nobumin/mtls_manager/internal/version"
	"github.com/nobumin/mtls_manager/mtls"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Options は Server の構成要素。
type Options struct {
	Config  *config.CA
	Issuer  *pki.Issuer
	DB      *store.DB
	EAB     *eab.Store
	Logs    *logbuf.Buffer
	Logger  *slog.Logger
	Started time.Time
	// Revoke は証明書を失効させる（acmeserver.Server.RevokeByAdmin。CRL に反映するため CA を通す）。
	// admin.operators を指定する場合は必須。
	Revoke func(serial string, reason int) error
	// Federation は連携版のトラストバンドル（自分の範囲を得るのに使う）。nil なら「連携」画面は無効。
	Federation *federation.Builder
}

// Server は管理画面。
type Server struct {
	cfg     *config.CA
	issuer  *pki.Issuer
	db      *store.DB
	eab     *eab.Store
	logs    *logbuf.Buffer
	log     *slog.Logger
	started time.Time
	tmpl    map[string]*template.Template
	allowed []netip.Prefix

	operators []string
	revoke    func(serial string, reason int) error
	csrfKey   []byte
	once      onceTokens
	fed       *federation.Builder
}

// New は Server を作る。
func New(o Options) (*Server, error) {
	if o.Config == nil || o.Issuer == nil || o.DB == nil || o.EAB == nil || o.Logs == nil {
		return nil, errors.New("admin: Config / Issuer / DB / EAB / Logs は必須")
	}
	if len(o.Config.Admin.AllowedClients) == 0 {
		return nil, errors.New("admin: admin.allowed_clients が空")
	}
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		cfg: o.Config, issuer: o.Issuer, db: o.DB, eab: o.EAB, logs: o.Logs, log: log,
		started: o.Started, allowed: o.Config.Admin.AllowedPrefixes(), tmpl: map[string]*template.Template{},
		operators: o.Config.Admin.Operators, revoke: o.Revoke, csrfKey: make([]byte, 32), fed: o.Federation,
	}
	if _, err := rand.Read(s.csrfKey); err != nil {
		return nil, err
	}
	if len(s.operators) > 0 {
		if s.revoke == nil {
			return nil, errors.New("admin: admin.operators を指定する場合は Revoke が必須")
		}
		if err := checkWritable(filepath.Dir(o.Config.EABFile)); err != nil {
			return nil, fmt.Errorf("admin.operators を使うには、eab_file のディレクトリに mtls-ca が書き込める必要がある: %w", err)
		}
		// ロックをかけて読めることも確かめる（root の mtlsctl が作ったロックファイルを開けないなど）。
		errCheck := errors.New("check")
		if err := eab.Update(o.Config.EABFile, func(*eab.File) error { return errCheck }); !errors.Is(err, errCheck) {
			return nil, fmt.Errorf("admin.operators を使うには、mtls-ca が eab_file を更新できる必要がある: %w", err)
		}
		if s.cfg.Federation.File != "" && s.fed != nil {
			if err := checkFederationWritable(s.cfg.Federation.File); err != nil {
				return nil, fmt.Errorf("admin.operators を使うには、%w", err)
			}
		}
	}
	for _, page := range []string{"dashboard", "certs", "eab", "logs", "eab_created", "federation"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/"+page+".html")
		if err != nil {
			return nil, err
		}
		s.tmpl[page] = t
	}
	return s, nil
}

// TLSConfig は管理画面用の tls.Config を返す。クライアント証明書を必須にし、
// この CA のルートにつながり、名前が admin.allowed_clients に一致する証明書だけを受け入れる。
func (s *Server) TLSConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(s.issuer.Root)
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		GetCertificate:   getCert,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        roots,
		VerifyConnection: mtls.VerifyPeer(s.cfg.Admin.AllowedClients),
	}
}

// Handler は HTTP ハンドラを返す。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.page("dashboard", s.dashboardData))
	mux.HandleFunc("GET /certs", s.page("certs", s.certsData))
	mux.HandleFunc("GET /eab", s.page("eab", s.eabData))
	mux.HandleFunc("GET /logs", s.page("logs", func(*http.Request) (any, error) { return nil, nil }))
	mux.HandleFunc("GET /api/logs", s.handleLogsAPI)
	mux.HandleFunc("POST /eab/create", s.handleEABCreate)
	mux.HandleFunc("POST /eab/revoke", s.handleEABRevoke)
	mux.HandleFunc("POST /certs/revoke", s.handleCertRevoke)
	mux.HandleFunc("GET /federation", s.page("federation", s.federationData))
	mux.HandleFunc("GET /federation/export", s.handleFedExport)
	mux.HandleFunc("POST /federation/import", s.handleFedImport)
	mux.HandleFunc("POST /federation/request", s.handleFedRequest)
	mux.HandleFunc("POST /federation/approve", s.handleFedApprove)
	mux.HandleFunc("POST /federation/suspend", s.handleFedSuspend)
	mux.HandleFunc("POST /federation/remove", s.handleFedRemove)
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	return s.restrictSource(s.requireAdmin(securityHeaders(mux)))
}

func (s *Server) restrictSource(next http.Handler) http.Handler {
	if len(s.allowed) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if addr, perr := netip.ParseAddr(host); err == nil && perr == nil {
			addr = addr.Unmap()
			for _, p := range s.allowed {
				if p.Contains(addr) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		s.log.Warn("管理画面: 許可されていない送信元からの接続を拒否", "category", "audit", "remote", r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}

// requireAdmin は検証済みのクライアント証明書があることを確かめ（TLS の設定と二重の確認）、
// アクセスを監査ログに残す。
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peers := mtls.PeerNames(r.TLS)
		if len(peers) == 0 {
			s.log.Warn("管理画面: クライアント証明書のない接続を拒否", "category", "audit", "remote", r.RemoteAddr)
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		// 失効させた管理者の証明書では入れない。管理画面は CA と同じプロセスで発行の記録を持っているので、
		// CRL を使わずにその場で確かめられる。この CA の発行の記録に無い証明書も拒否する。
		if reason := s.certRejected(r.TLS.PeerCertificates[0]); reason != "" {
			s.log.Warn("管理画面: "+reason+"での接続を拒否", "category", "audit", "admin", peers[0],
				"serial", fmt.Sprintf("%x", r.TLS.PeerCertificates[0].SerialNumber), "remote", r.RemoteAddr)
			http.Error(w, "forbidden: "+reason, http.StatusForbidden)
			return
		}
		// API のポーリングは頻繁なので debug にとどめる（画面の表示は info で残す）。
		level := slog.LevelInfo
		if r.URL.Path == "/api/logs" {
			level = slog.LevelDebug
		}
		s.log.Log(r.Context(), level, "管理画面へのアクセス", "category", "audit",
			"admin", peers[0], "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

// securityHeaders はブラウザ側の防御を有効にする。外部のスクリプト・スタイルは読み込まない。
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(w, r)
	})
}

type pageData struct {
	Title    string
	Page     string
	Admin    string
	Version  string
	Now      time.Time
	Operator bool   // 変更の操作ができる管理者か
	CSRF     string // 変更の操作のフォームに埋め込むトークン
	Once     string // EAB 鍵の発行フォームの使い捨てトークン
	Flash    string // 直前の操作の結果
	FlashBad bool
	Data     any
}

func (s *Server) page(name string, load func(*http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := load(r)
		if err != nil {
			s.log.Error("管理画面: データを読めない", "page", name, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.render(w, r, http.StatusOK, name, data, flashMessage(r), false)
	}
}

var titles = map[string]string{"dashboard": "概要", "certs": "発行済み証明書", "eab": "EAB 鍵", "logs": "ログ", "eab_created": "EAB 鍵を発行した", "federation": "連携"}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, data any, flash string, flashBad bool) {
	admin := mtls.PeerNames(r.TLS)[0]
	pd := pageData{
		Title: titles[name], Page: name, Admin: admin, Version: version.Version, Now: time.Now(),
		Operator: s.isOperator(admin), CSRF: s.csrfToken(admin), Once: newOnce(), Flash: flash, FlashBad: flashBad, Data: data,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl[name].Execute(w, pd); err != nil {
		s.log.Error("管理画面: 画面を作れない", "page", name, "err", err)
	}
}

// certRejected は管理者の証明書を発行の記録と照らし、拒否する理由を返す（問題がなければ空）。
func (s *Server) certRejected(c *x509.Certificate) string {
	rec, err := s.db.Cert(fmt.Sprintf("%x", c.SerialNumber))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "発行の記録が無い証明書"
	case err != nil:
		s.log.Error("管理画面: 発行の記録を読めない", "err", err)
		return "発行の記録を確かめられない証明書"
	case rec.Revoked:
		return "失効した証明書"
	case rec.Pending:
		return "発行を完了していない証明書"
	}
	return s.eabRejected(rec, c)
}

// eabRejected は、管理者の証明書を発行したアカウントの EAB 鍵が、今もその名前を完全一致で許可しているかを確かめる。
// 発行の時点（acmeserver の checkNames）と同じ条件をログインの時点でも確かめることで、次の場合に入れないようにする。
//   - EAB 鍵を取り消した（その鍵で取った管理者の証明書でも、すぐに入れなくなる）
//   - admin.allowed_clients を後から広げ、サーバ用のワイルドカードの鍵で発行済みの証明書が管理者の名前に一致した
func (s *Server) eabRejected(rec *store.Cert, c *x509.Certificate) string {
	acct, err := s.db.Account(rec.AccountID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("管理画面: アカウントを読めない", "err", err)
		}
		return "発行したアカウントを確かめられない証明書"
	}
	k, ok, err := s.eab.Lookup(acct.EABKeyID)
	switch {
	case err != nil:
		s.log.Error("管理画面: EAB 鍵ファイルを読めない", "err", err)
		return "EAB 鍵を確かめられない証明書"
	case !ok:
		return "取り消した EAB 鍵で発行した証明書"
	}
	for _, n := range c.DNSNames {
		if names.MatchAny(s.cfg.Admin.AllowedClients, n) && !k.PermitsExactly(n) {
			return "管理者の名前を完全一致で許可していない EAB 鍵で発行した証明書"
		}
	}
	return ""
}
