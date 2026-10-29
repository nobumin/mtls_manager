// Package admin は mtls-ca の管理画面（閲覧用の Web 画面）を提供する。
//
//   - ACME とは別のポートで待ち受ける（localhost か管理用のサブネットのアドレスで待ち受ける前提）
//   - ログインはこの CA が発行したクライアント証明書による mTLS。パスワードは使わない。
//     入れる管理者は設定の admin.allowed_clients（証明書の名前のパターン）で限る
//   - アクセスはすべて監査ログ（category=audit）に残す
//   - 現在は閲覧のみ（状態の概要、発行済み証明書、EAB 鍵、ログ）。秘密情報（鍵・HMAC）は表示しない
package admin

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/eab"
	"github.com/nobumin/mtls_manager/internal/logbuf"
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
	}
	for _, page := range []string{"dashboard", "certs", "eab", "logs"} {
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
	Title   string
	Page    string
	Admin   string
	Version string
	Now     time.Time
	Data    any
}

func (s *Server) page(name string, load func(*http.Request) (any, error)) http.HandlerFunc {
	titles := map[string]string{"dashboard": "概要", "certs": "発行済み証明書", "eab": "EAB 鍵", "logs": "ログ"}
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := load(r)
		if err != nil {
			s.log.Error("管理画面: データを読めない", "page", name, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pd := pageData{Title: titles[name], Page: name, Admin: mtls.PeerNames(r.TLS)[0], Version: version.Version, Now: time.Now(), Data: data}
		if err := s.tmpl[name].Execute(w, pd); err != nil {
			s.log.Error("管理画面: 画面を作れない", "page", name, "err", err)
		}
	}
}
