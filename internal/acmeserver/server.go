// Package acmeserver は mTLS 用の証明書を発行する ACME サーバ（RFC 8555 のうち必要な部分）を実装する。
//
// 対応範囲:
//   - External Account Binding 必須（事前に配った鍵が無いとアカウントを作れない）
//   - 識別子は dns のみ（ワイルドカード不可）。発行してよいドメインと、EAB 鍵ごとの名前で二重に制限する
//   - チャレンジは http-01 / tls-alpn-01
//   - 失効（アカウント鍵による revokeCert）と CRL の配布
//
// 非対応: keyChange（アカウント鍵の交換）、証明書の鍵による失効、事前認可（newAuthz）。
package acmeserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/eab"
	"github.com/nobumin/mtls_manager/internal/federation"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/store"
)

const (
	pathDirectory  = "/acme/directory"
	pathNewNonce   = "/acme/new-nonce"
	pathNewAccount = "/acme/new-account"
	pathAccount    = "/acme/account/"
	pathNewOrder   = "/acme/new-order"
	pathOrder      = "/acme/order/"
	pathAuthz      = "/acme/authz/"
	pathChall      = "/acme/chall/"
	pathCert       = "/acme/cert/"
	pathRevoke     = "/acme/revoke-cert"
	pathCRL        = "/crl"
	pathHealth     = "/healthz"

	orderLifetime = time.Hour
	// retention は期限切れの注文・認可・発行履歴を残す期間。
	retention = 7 * 24 * time.Hour
)

// Options は Server の構成要素。
type Options struct {
	Config    *config.CA
	Issuer    *pki.Issuer
	DB        *store.DB
	EAB       *eab.Store
	Logger    *slog.Logger
	Validator *Validator // nil なら Config から作る
	// Federation は連携版のトラストバンドル（nil なら /federation/bundle は 404）。
	Federation *federation.Builder
}

// Server は ACME サーバ。
type Server struct {
	cfg       *config.CA
	issuer    *pki.Issuer
	db        *store.DB
	eab       *eab.Store
	log       *slog.Logger
	validator *Validator
	fed       *federation.Builder
	nonces    *nonceStore
	allowed   []netip.Prefix

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	crlMu    sync.Mutex
	crlDER   []byte
	crlAt    time.Time
	crlDirty bool
}

// New は Server を作る。
func New(o Options) (*Server, error) {
	if o.Config == nil || o.Issuer == nil || o.DB == nil || o.EAB == nil {
		return nil, errors.New("acmeserver: Config / Issuer / DB / EAB は必須")
	}
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	v := o.Validator
	if v == nil {
		c := o.Config.Challenge
		v = &Validator{HTTPPort: c.HTTP01Port, TLSALPNPort: c.TLSALPN01Port, Timeout: c.Timeout.D(), Resolver: c.Resolver}
	}
	// 前回の停止で確認中のまま残ったチャレンジを、クライアントがやり直せるよう pending に戻す。
	if n, err := o.DB.ResetProcessingChallenges(); err != nil {
		return nil, fmt.Errorf("確認中のチャレンジを戻せない: %w", err)
	} else if n > 0 {
		log.Info("確認の途中で止まっていたチャレンジを pending に戻した", "count", n)
	}
	warnAdminOverlaps(log, o.EAB, o.Config.Admin.AllowedClients)
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg: o.Config, issuer: o.Issuer, db: o.DB, eab: o.EAB, log: log, validator: v,
		fed: o.Federation,
		nonces: newNonceStore(), allowed: o.Config.AllowedPrefixes(),
		ctx: ctx, cancel: cancel, crlDirty: true,
	}, nil
}

// Close は実行中のチャレンジの確認を止めて待つ。
func (s *Server) Close() {
	s.cancel()
	s.wg.Wait()
}

// RunCleanup は期限切れのレコードを定期的に消す。ctx が終わるまで戻らない。
func (s *Server) RunCleanup(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := s.db.Cleanup(time.Now(), retention); err != nil {
			s.log.Error("期限切れレコードの削除に失敗", "err", err)
		} else if n > 0 {
			s.log.Info("期限切れレコードを削除", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) url(path string) string { return s.cfg.ExternalURL + path }

// Handler は HTTP ハンドラを返す。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+pathDirectory, s.handleDirectory)
	mux.HandleFunc("HEAD "+pathNewNonce, s.handleNewNonce)
	mux.HandleFunc("GET "+pathNewNonce, s.handleNewNonce)
	mux.HandleFunc("POST "+pathNewAccount, s.post(true, s.handleNewAccount))
	mux.HandleFunc("POST "+pathAccount+"{id}", s.post(false, s.handleAccount))
	mux.HandleFunc("POST "+pathAccount+"{id}/orders", s.post(false, s.handleAccountOrders))
	mux.HandleFunc("POST "+pathNewOrder, s.post(false, s.handleNewOrder))
	mux.HandleFunc("POST "+pathOrder+"{id}", s.post(false, s.handleOrder))
	mux.HandleFunc("POST "+pathOrder+"{id}/finalize", s.post(false, s.handleFinalize))
	mux.HandleFunc("POST "+pathAuthz+"{id}", s.post(false, s.handleAuthz))
	mux.HandleFunc("POST "+pathChall+"{authz}/{type}", s.post(false, s.handleChallenge))
	mux.HandleFunc("POST "+pathCert+"{serial}", s.post(false, s.handleCert))
	mux.HandleFunc("POST "+pathRevoke, s.post(false, s.handleRevoke))
	mux.HandleFunc("GET "+pathCRL, s.handleCRL)
	mux.HandleFunc("GET "+pathFederationBundle, s.handleFederationBundle)
	mux.HandleFunc("GET "+pathHealth, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	return s.restrictSource(s.acmeHeaders(mux))
}

// restrictSource は allowed_client_cidrs 以外からの接続を拒否する。
// 送信元は TCP の接続元で判定する（X-Forwarded-For は信用しない）。
func (s *Server) restrictSource(next http.Handler) http.Handler {
	if len(s.allowed) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		addr, perr := netip.ParseAddr(host)
		if err == nil && perr == nil {
			addr = addr.Unmap()
			for _, p := range s.allowed {
				if p.Contains(addr) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		s.log.Warn("許可されていない送信元からの接続を拒否", "remote", r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}

// acmeHeaders は ACME の全応答に Replay-Nonce などを付ける（RFC 8555 §6.5, §7.1）。
func (s *Server) acmeHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pathCRL && r.URL.Path != pathHealth {
			h := w.Header()
			h.Set("Replay-Nonce", s.nonces.issue())
			h.Set("Cache-Control", "no-store")
			h.Add("Link", `<`+s.url(pathDirectory)+`>;rel="index"`)
		}
		next.ServeHTTP(w, r)
	})
}

// reply は POST ハンドラの応答。
type reply struct {
	status      int
	body        any
	location    string
	up          string
	retryAfter  bool // 処理中なので 1 秒後に問い合わせてよい（RFC 8555 §8.2）
	raw         []byte
	contentType string
}

func (s *Server) post(wantJWK bool, h func(*http.Request, *request) (*reply, *problem)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, p := s.verify(r, wantJWK)
		if p != nil {
			s.writeProblem(w, r, p)
			return
		}
		rep, p := h(r, req)
		if p != nil {
			s.writeProblem(w, r, p)
			return
		}
		if rep.location != "" {
			w.Header().Set("Location", rep.location)
		}
		if rep.retryAfter {
			w.Header().Set("Retry-After", "1")
		}
		if rep.up != "" {
			w.Header().Add("Link", `<`+rep.up+`>;rel="up"`)
		}
		if rep.raw != nil {
			w.Header().Set("Content-Type", rep.contentType)
			w.WriteHeader(rep.status)
			_, _ = w.Write(rep.raw)
			return
		}
		writeJSON(w, rep.status, rep.body)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeProblem(w http.ResponseWriter, r *http.Request, p *problem) {
	if p.Status == 0 {
		p.Status = http.StatusBadRequest
	}
	lvl := slog.LevelInfo
	if p.Status >= 500 {
		lvl = slog.LevelError
	}
	s.log.Log(r.Context(), lvl, "ACME エラー", "path", r.URL.Path, "type", p.Type, "detail", p.Detail, "remote", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Server) handleDirectory(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"newNonce":   s.url(pathNewNonce),
		"newAccount": s.url(pathNewAccount),
		"newOrder":   s.url(pathNewOrder),
		"revokeCert": s.url(pathRevoke),
		"meta": map[string]any{
			"externalAccountRequired": true,
		},
	})
}

func (s *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleCRL は中間 CA が署名した CRL（DER）を返す。失効があったとき、または有効期間の半分が過ぎたときに作り直す。
func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	der, err := s.currentCRL()
	if err != nil {
		s.log.Error("CRL を作れない", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	_, _ = w.Write(der)
}

func (s *Server) currentCRL() ([]byte, error) {
	s.crlMu.Lock()
	defer s.crlMu.Unlock()
	validity := s.cfg.CRL.Validity.D()
	if !s.crlDirty && time.Since(s.crlAt) < validity/2 {
		return s.crlDER, nil
	}
	now := time.Now()
	revoked, err := s.db.RevokedCerts(now)
	if err != nil {
		return nil, err
	}
	entries := make([]pki.RevokedEntry, 0, len(revoked))
	for _, c := range revoked {
		serial, ok := new(big.Int).SetString(c.Serial, 16)
		if !ok {
			continue
		}
		entries = append(entries, pki.RevokedEntry{Serial: serial, RevokedAt: c.RevokedAt, Reason: c.Reason})
	}
	der, err := s.issuer.CreateCRL(entries, big.NewInt(now.UnixNano()), validity)
	if err != nil {
		return nil, err
	}
	s.crlDER, s.crlAt, s.crlDirty = der, now, false
	return der, nil
}

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// warnAdminOverlaps は、管理者の名前と重なるワイルドカードを持つ EAB 鍵を警告する。
// そうした鍵でも管理者の名前の証明書は発行しない（checkNames）が、意図しない設定の可能性が高い。
func warnAdminOverlaps(log *slog.Logger, store *eab.Store, admins []string) {
	if len(admins) == 0 {
		return
	}
	keys, err := store.Keys()
	if err != nil {
		return
	}
	for _, k := range keys {
		if ov := k.WildcardOverlaps(admins); len(ov) > 0 {
			log.Warn("EAB 鍵のワイルドカードが管理者の名前と重なっている（この鍵では管理者の名前の証明書は発行しない。管理者の名前はサーバと別のサブドメインにする）",
				"eab_kid", k.KID, "note", k.Note, "patterns", ov, "admin_clients", admins)
		}
	}
}
