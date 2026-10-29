package admin_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobumin/mtls_manager/internal/acmeserver"
	"github.com/nobumin/mtls_manager/internal/admin"
	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/eab"
	"github.com/nobumin/mtls_manager/internal/logbuf"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/store"
	"github.com/nobumin/mtls_manager/internal/testca"
)

const (
	adminName = "admin1.internal.example.com"
	caName    = "ca." + testca.Domain
)

type env struct {
	addr    string
	issuer  *pki.Issuer
	logs    *logbuf.Buffer
	eabHMAC string
	eabKID  string
	eabPath string
	db      *store.DB
}

func start(t *testing.T, mutate func(*config.CA)) *env {
	t.Helper()
	dir := t.TempDir()
	iss := testca.NewIssuer(t, testca.Domain)
	eabPath := filepath.Join(dir, "eab.json")
	var hmac, kid string
	if err := eab.Update(eabPath, func(f *eab.File) error {
		k, err := f.Add([]string{"web1." + testca.Domain}, "web1（Web サーバ）")
		hmac, kid = k.HMAC, k.KID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.CA{
		ExternalURL: "https://" + caName + ":8443", DataDir: filepath.Join(dir, "data"),
		RootCert: "r", IntermediateCert: "i", IntermediateKey: "k", EABFile: eabPath,
		Policy: config.CAPolicy{AllowedDomains: []string{testca.Domain}},
		Admin:  config.CAAdmin{Listen: "127.0.0.1:0", AllowedClients: []string{adminName}},
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
	// 発行済みの証明書を 1 件入れておく。
	if err := db.CreateOrder(&store.Order{ID: "o1", Status: store.StatusProcessing}, nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := db.FinalizeOrder("o1", &store.Cert{Serial: "abc123", Names: []string{"web1." + testca.Domain}, NotBefore: now, NotAfter: now.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	eabStore, err := eab.NewStore(eabPath)
	if err != nil {
		t.Fatal(err)
	}
	logs := logbuf.New(1000)
	log := slog.New(logs.Handler(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.Info("所有確認に失敗", "name", "web9."+testca.Domain)
	e := &env{issuer: iss, logs: logs, eabHMAC: hmac, eabKID: kid, eabPath: eabPath, db: db}
	revoke := func(serial string, reason int) error { return db.RevokeCert(serial, reason, nil) }
	srv, err := admin.New(admin.Options{Config: cfg, Issuer: iss, DB: db, EAB: eabStore, Logs: logs, Logger: log, Started: now, Revoke: revoke})
	if err != nil {
		t.Fatal(err)
	}
	self, err := acmeserver.NewSelfCert(iss, []string{caName}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.TLSConfig(self.GetCertificate))
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	e.addr = ln.Addr().String()
	return e
}

// client は name の証明書を持つ管理者のブラウザを模す（name が空なら証明書なし）。
func (e *env) client(t *testing.T, iss *pki.Issuer, name string) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(e.issuer.Root)
	tc := &tls.Config{RootCAs: roots, ServerName: caName}
	if name != "" {
		key, _ := pki.GenerateKey(pki.KeyECDSAP256)
		leaf, err := iss.IssueLeaf(key.Public(), []string{name}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		tc.Certificates = []tls.Certificate{{Certificate: [][]byte{leaf.Raw, iss.Cert.Raw}, PrivateKey: key}}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}
}

func get(t *testing.T, c *http.Client, url string) (*http.Response, string) {
	t.Helper()
	res, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

func TestAdminPagesForAllowedAdmin(t *testing.T) {
	e := start(t, nil)
	c := e.client(t, e.issuer, adminName)
	base := "https://" + e.addr

	for path, want := range map[string]string{
		"/":      "有効な証明書",
		"/certs": "web1." + testca.Domain,
		"/eab":   "web1（Web サーバ）",
		"/logs":  "/static/logs.js",
	} {
		res, body := get(t, c, base+path)
		if res.StatusCode != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("%s: status=%d、%q を含まない", path, res.StatusCode, want)
		}
		if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
			t.Errorf("%s: CSP が無い: %q", path, csp)
		}
	}
	// EAB の HMAC 鍵（秘密情報）は表示しない。
	if _, body := get(t, c, base+"/eab"); strings.Contains(body, e.eabHMAC) {
		t.Fatal("EAB の HMAC 鍵が画面に出ている")
	}
	// 静的ファイル（外部から読み込まない）。
	if res, _ := get(t, c, base+"/static/app.css"); res.StatusCode != http.StatusOK {
		t.Errorf("app.css: %d", res.StatusCode)
	}
}

func TestLogsAPIAndAudit(t *testing.T) {
	e := start(t, nil)
	c := e.client(t, e.issuer, adminName)
	base := "https://" + e.addr
	get(t, c, base+"/certs") // 監査ログが残る

	res, body := get(t, c, base+"/api/logs?level=INFO")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var data struct {
		Entries []struct {
			Seq   uint64
			Msg   string
			Attrs []logbuf.Attr
		}
	}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		t.Fatal(err)
	}
	var sawLog, sawAudit bool
	for _, en := range data.Entries {
		if en.Msg == "所有確認に失敗" {
			sawLog = true
		}
		if en.Msg == "管理画面へのアクセス" {
			for _, a := range en.Attrs {
				if a.Key == "admin" && a.Value == adminName {
					sawAudit = true
				}
			}
		}
	}
	if !sawLog || !sawAudit {
		t.Fatalf("ログ・監査ログが返らない（log=%v audit=%v）: %s", sawLog, sawAudit, body)
	}
	// 文字列での絞り込みと、連番以降の取得。
	_, body = get(t, c, base+"/api/logs?q=web9")
	if !strings.Contains(body, "所有確認に失敗") || strings.Contains(body, "管理画面へのアクセス") {
		t.Errorf("文字列での絞り込みが効かない: %s", body)
	}
	if res, _ := get(t, c, base+"/api/logs?level=bogus"); res.StatusCode != http.StatusBadRequest {
		t.Errorf("不正な level: %d", res.StatusCode)
	}
}

func TestAdminRejectsOthers(t *testing.T) {
	e := start(t, nil)
	base := "https://" + e.addr

	// 許可されていない名前の証明書（同じ CA が発行していても）。
	if _, err := e.client(t, e.issuer, "web1."+testca.Domain).Get(base + "/"); err == nil {
		t.Error("許可されていない名前の証明書で入れた")
	}
	// クライアント証明書なし。
	if _, err := e.client(t, e.issuer, "").Get(base + "/"); err == nil {
		t.Error("クライアント証明書なしで入れた")
	}
	// 別の CA が発行した、同じ名前の証明書。
	other := testca.NewIssuer(t, "example.com")
	if _, err := e.client(t, other, adminName).Get(base + "/"); err == nil {
		t.Error("別の CA の証明書で入れた")
	}
	// 拒否された接続の記録（TLS の段階で拒否されるので、HTTP の監査ログには残らない）は
	// http.Server の ErrorLog に出る。ここでは入れないことだけを確かめる。
}

func TestAdminSourceRestriction(t *testing.T) {
	e := start(t, func(c *config.CA) { c.Admin.AllowedCIDRs = []string{"10.0.0.0/8"} })
	res, _ := get(t, e.client(t, e.issuer, adminName), "https://"+e.addr+"/")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("許可されていない送信元からの接続の status = %d", res.StatusCode)
	}
	if got := e.logs.Find(logbuf.Query{Text: "許可されていない送信元"}); len(got) == 0 {
		t.Error("拒否が監査ログに残っていない")
	}
}

func TestAdminConfigRequiresAllowedClients(t *testing.T) {
	c := &config.CA{
		ExternalURL: "https://ca.example.com:8443", DataDir: "d", RootCert: "r", IntermediateCert: "i", IntermediateKey: "k", EABFile: "e",
		Policy: config.CAPolicy{AllowedDomains: []string{"example.com"}},
		Admin:  config.CAAdmin{Listen: "127.0.0.1:9443"},
	}
	if err := c.Complete(); err == nil || !strings.Contains(err.Error(), "allowed_clients") {
		t.Fatalf("allowed_clients なしで管理画面を有効にできた: %v", err)
	}

}
