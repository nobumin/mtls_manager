// Package testca はテスト用に mtls-ca をプロセス内で起動する。鍵・証明書はテストの実行時にその場で作る
// （リポジトリに鍵ファイルを置かない）。
package testca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nobumin/mtls_manager/internal/acmeserver"
	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/eab"
	"github.com/nobumin/mtls_manager/internal/federation"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/store"
)

// Domain はテスト用の CA が発行できるドメイン。
const Domain = "internal.example.com"

// CA は起動したテスト用 CA。
type CA struct {
	URL          string // https://ca.internal.example.com:port
	Addr         string // 実際の接続先 127.0.0.1:port
	DirectoryURL string
	Issuer       *pki.Issuer
	Server       *acmeserver.Server
	EABFile      string
	RootFile     string
	Dir          string

	mu      sync.Mutex
	targets map[string]string // チャレンジの種類 → 接続先アドレス
}

// Start は CA を起動する。チャレンジの接続先は SetTarget で差し替える（名前解決をしない）。
func Start(t testing.TB, mutate func(*config.CA)) *CA {
	t.Helper()
	dir := t.TempDir()
	iss := NewIssuer(t, Domain)
	ca := &CA{Issuer: iss, Dir: dir, targets: map[string]string{}}

	ca.RootFile = filepath.Join(dir, "root.crt")
	if err := os.WriteFile(ca.RootFile, pki.EncodeCertsPEM(iss.Root), 0o644); err != nil {
		t.Fatal(err)
	}
	ca.EABFile = filepath.Join(dir, "eab.json")
	if err := (&eab.File{}).Save(ca.EABFile); err != nil {
		t.Fatal(err)
	}

	var handler http.Handler
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	leafKey, _ := pki.GenerateKey(pki.KeyECDSAP256)
	leaf, err := iss.IssueLeaf(leafKey.Public(), []string{"ca." + Domain}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw, iss.Cert.Raw}, PrivateKey: leafKey, Leaf: leaf}}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	// クライアントからは ca.internal.example.com として見せ、接続だけ 127.0.0.1 に向ける（Addr / HTTPClient）。
	ca.Addr = ts.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(ca.Addr)
	ca.URL = "https://ca." + Domain + ":" + port
	ca.DirectoryURL = ca.URL + "/acme/directory"

	cfg := &config.CA{
		ExternalURL:      ca.URL,
		Hostnames:        []string{"ca." + Domain},
		DataDir:          filepath.Join(dir, "data"),
		RootCert:         ca.RootFile,
		IntermediateCert: "unused",
		IntermediateKey:  "unused",
		EABFile:          ca.EABFile,
		Policy:           config.CAPolicy{AllowedDomains: []string{Domain}},
		Challenge:        config.CAChallenge{Attempts: 1, Timeout: config.Duration(5 * time.Second)},
	}
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Complete(); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	eabStore, err := eab.NewStore(ca.EABFile)
	if err != nil {
		t.Fatal(err)
	}
	v := &acmeserver.Validator{
		HTTPPort: cfg.Challenge.HTTP01Port, TLSALPNPort: cfg.Challenge.TLSALPN01Port, Timeout: cfg.Challenge.Timeout.D(),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			typ := config.ChallengeHTTP01
			if port == strconv.Itoa(cfg.Challenge.TLSALPN01Port) {
				typ = config.ChallengeTLSALPN01
			}
			ca.mu.Lock()
			target := ca.targets[typ]
			ca.mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	var fed *federation.Builder
	if cfg.Federation.File != "" {
		st, err := federation.NewStore(cfg.Federation.File)
		if err != nil {
			t.Fatal(err)
		}
		if fed, err = federation.NewBuilder(st, iss.Cert, iss.Key, []*x509.Certificate{iss.Root}, cfg.Federation.BundleValidity.D(), logger); err != nil {
			t.Fatal(err)
		}
	}
	srv, err := acmeserver.New(acmeserver.Options{Config: cfg, Issuer: iss, DB: db, EAB: eabStore, Logger: logger, Validator: v, Federation: fed})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ca.Server = srv
	handler = srv.Handler()
	return ca
}

// SetTarget はチャレンジの種類ごとに、CA が接続するアドレスを設定する。
func (c *CA) SetTarget(challengeType, addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.targets[challengeType] = addr
}

// AddEAB は EAB 鍵を追加し、kid と HMAC 鍵を返す。
func (c *CA) AddEAB(t testing.TB, patterns ...string) (kid string, hmacKey []byte, hmacB64 string) {
	t.Helper()
	f, err := eab.Load(c.EABFile)
	if err != nil {
		t.Fatal(err)
	}
	k, err := f.Add(patterns, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Save(c.EABFile); err != nil {
		t.Fatal(err)
	}
	touch(t, c.EABFile)
	key, err := k.HMACKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.KID, key, k.HMAC
}

// RemoveEAB は EAB 鍵を削除する（ホストの取り消し）。
func (c *CA) RemoveEAB(t testing.TB, kid string) {
	t.Helper()
	f, err := eab.Load(c.EABFile)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Remove(kid) {
		t.Fatalf("EAB 鍵 %s が無い", kid)
	}
	if err := f.Save(c.EABFile); err != nil {
		t.Fatal(err)
	}
	touch(t, c.EABFile)
}

// touch は更新時刻を確実に進める（同じ時刻・同じサイズの書き換えでも変更を検出させる）。
func touch(t testing.TB, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	next := fi.ModTime().Add(time.Second)
	if err := os.Chtimes(path, next, next); err != nil {
		t.Fatal(err)
	}
}

// RootPool はルート CA だけを含むプールを返す。
func (c *CA) RootPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.Issuer.Root)
	return p
}

// HTTPClient は CA に接続できる HTTP クライアントを返す。
func (c *CA) HTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: c.RootPool()},
		DialContext:     c.DialContext,
	}}
}

// DialContext は宛先を問わず CA に接続する。
func (c *CA) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, c.Addr)
}

// NewIssuer はテスト用のルート CA と中間 CA を作る。
func NewIssuer(t testing.TB, permitted ...string) *pki.Issuer {
	t.Helper()
	rootKey, err := pki.GenerateKey(pki.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	root, err := pki.CreateRoot(rootKey, pki.RootOptions{CommonName: "Test Root", Validity: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	interKey, err := pki.GenerateKey(pki.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := pki.CreateCSR(interKey, "Test Intermediate", "")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := pki.SignIntermediate(root, rootKey, csr, pki.IntermediateOptions{Validity: 3 * 24 * time.Hour, PermittedDomains: permitted})
	if err != nil {
		t.Fatal(err)
	}
	iss, err := pki.NewIssuer(inter, interKey, root)
	if err != nil {
		t.Fatal(err)
	}
	return iss
}
