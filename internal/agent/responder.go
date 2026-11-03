package agent

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/i18n"
)

// responder はチャレンジに応答する。所有確認の間だけ待ち受ける（またはファイルを置く）。
type responder struct {
	cfg    config.AgentChallenge
	client *acme.Client

	mu      sync.Mutex
	http01  map[string]string          // パス → 応答
	alpn    map[string]tls.Certificate // 名前 → 検証用証明書
	files   []string                   // webroot に置いたファイル
	closeFn func()
}

func newResponder(cfg config.AgentChallenge, c *acme.Client) (*responder, error) {
	r := &responder{cfg: cfg, client: c, http01: map[string]string{}, alpn: map[string]tls.Certificate{}}
	if cfg.Webroot != "" {
		return r, nil
	}
	switch cfg.Type {
	case config.ChallengeHTTP01:
		ln, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			return nil, fmt.Errorf(i18n.T("http-01 の応答用に %s を開けない（権限・ポートの競合を確認する）: %w", "cannot open %s to answer http-01 (check permissions and port conflicts): %w"), cfg.Listen, err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(r.serveHTTP01), ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		r.closeFn = func() { _ = srv.Close() }
	case config.ChallengeTLSALPN01:
		ln, err := tls.Listen("tcp", cfg.Listen, &tls.Config{
			NextProtos:     []string{acme.ALPNProto},
			MinVersion:     tls.VersionTLS12,
			GetCertificate: r.alpnCertificate,
		})
		if err != nil {
			return nil, fmt.Errorf(i18n.T("tls-alpn-01 の応答用に %s を開けない（権限・ポートの競合を確認する）: %w", "cannot open %s to answer tls-alpn-01 (check permissions and port conflicts): %w"), cfg.Listen, err)
		}
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
					_ = conn.(*tls.Conn).Handshake()
				}()
			}
		}()
		r.closeFn = func() { _ = ln.Close() }
	}
	return r, nil
}

func (r *responder) add(token, name string) error {
	switch r.cfg.Type {
	case config.ChallengeHTTP01:
		body, err := r.client.HTTP01ChallengeResponse(token)
		if err != nil {
			return err
		}
		path := r.client.HTTP01ChallengePath(token)
		if r.cfg.Webroot != "" {
			return r.writeWebroot(path, body)
		}
		r.mu.Lock()
		r.http01[path] = body
		r.mu.Unlock()
	case config.ChallengeTLSALPN01:
		cert, err := r.client.TLSALPN01ChallengeCert(token, name)
		if err != nil {
			return err
		}
		r.mu.Lock()
		r.alpn[name] = cert
		r.mu.Unlock()
	}
	return nil
}

func (r *responder) writeWebroot(urlPath, body string) error {
	rel := strings.TrimPrefix(urlPath, "/")
	full := filepath.Join(r.cfg.Webroot, filepath.FromSlash(rel))
	if !strings.HasPrefix(full, filepath.Clean(r.cfg.Webroot)+string(filepath.Separator)) {
		return errors.New(i18n.T("webroot の外に書こうとした", "attempted to write outside the webroot"))
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		return err
	}
	r.mu.Lock()
	r.files = append(r.files, full)
	r.mu.Unlock()
	return nil
}

func (r *responder) serveHTTP01(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	body, ok := r.http01[req.URL.Path]
	r.mu.Unlock()
	if !ok || req.Method != http.MethodGet {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, body)
}

func (r *responder) alpnCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !slices.Contains(hello.SupportedProtos, acme.ALPNProto) {
		return nil, errors.New(i18n.T("acme-tls/1 以外の接続は受け付けない", "only acme-tls/1 connections are accepted"))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cert, ok := r.alpn[strings.ToLower(hello.ServerName)]
	if !ok {
		return nil, fmt.Errorf(i18n.T("%q の検証用証明書が無い", "no validation certificate for %q"), hello.ServerName)
	}
	return &cert, nil
}

// close は待ち受けを止め、webroot に置いたファイルを消す。何度呼んでもよい。
func (r *responder) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closeFn != nil {
		r.closeFn()
		r.closeFn = nil
	}
	for _, f := range r.files {
		_ = os.Remove(f)
	}
	r.files = nil
}
