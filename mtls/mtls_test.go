package mtls_test

import (
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/testca"
	"github.com/nobumin/mtls_manager/mtls"
)

type files struct{ cert, key, ca string }

func writeLeaf(t *testing.T, iss *pki.Issuer, dir, name string) files {
	t.Helper()
	key, err := pki.GenerateKey(pki.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := iss.IssueLeaf(key.Public(), []string{name}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := pki.MarshalPrivateKeyPEM(key)
	f := files{cert: filepath.Join(dir, name+".crt"), key: filepath.Join(dir, name+".key"), ca: filepath.Join(dir, "ca.pem")}
	if err := pki.WriteFileAtomic(f.cert, pki.EncodeCertsPEM(leaf, iss.Cert), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteFileAtomic(f.key, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.ca, pki.EncodeCertsPEM(iss.Root), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func startServer(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Join(mtls.PeerNames(r.TLS), ","))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func client(t *testing.T, f files, serverName string) *http.Client {
	t.Helper()
	cfg, err := mtls.NewClientTLSConfig(mtls.Config{CertFile: f.cert, KeyFile: f.key, CAFile: f.ca})
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerName = serverName
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

func TestMutualTLS(t *testing.T) {
	dir := t.TempDir()
	iss := testca.NewIssuer(t, testca.Domain)
	srvFiles := writeLeaf(t, iss, dir, "api."+testca.Domain)
	allowed := writeLeaf(t, iss, dir, "app1."+testca.Domain)
	denied := writeLeaf(t, iss, dir, "other."+testca.Domain)

	cfg, err := mtls.NewServerTLSConfig(mtls.Config{
		CertFile: srvFiles.cert, KeyFile: srvFiles.key, CAFile: srvFiles.ca,
		AllowedPeers: []string{"app1." + testca.Domain},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, cfg)
	url := "https://" + addr + "/"

	res, err := client(t, allowed, "api."+testca.Domain).Get(url)
	if err != nil {
		t.Fatalf("許可された相手が接続できない: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "app1."+testca.Domain {
		t.Errorf("PeerNames = %q", body)
	}

	if _, err := client(t, denied, "api."+testca.Domain).Get(url); err == nil {
		t.Error("許可されていない相手が接続できた")
	}

	// クライアント証明書なしでは接続できない。
	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: cfg.ClientCAs, ServerName: "api." + testca.Domain}}, Timeout: 5 * time.Second}
	if _, err := noCert.Get(url); err == nil {
		t.Error("クライアント証明書なしで接続できた")
	}

	// 別の CA の証明書では接続できない。
	otherIss := testca.NewIssuer(t, testca.Domain)
	foreign := writeLeaf(t, otherIss, t.TempDir(), "app1."+testca.Domain)
	foreignCfg, _ := mtls.NewClientTLSConfig(mtls.Config{CertFile: foreign.cert, KeyFile: foreign.key, CAFile: srvFiles.ca})
	foreignCfg.ServerName = "api." + testca.Domain
	if _, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: foreignCfg}, Timeout: 5 * time.Second}).Get(url); err == nil {
		t.Error("別の CA の証明書で接続できた")
	}

	// ホスト名が証明書と違えば、クライアント側が拒否する。
	if _, err := client(t, allowed, "wrong."+testca.Domain).Get(url); err == nil {
		t.Error("ホスト名の不一致を検出しなかった")
	}
}

func TestServerRequiresAllowedPeers(t *testing.T) {
	dir := t.TempDir()
	iss := testca.NewIssuer(t, testca.Domain)
	f := writeLeaf(t, iss, dir, "api."+testca.Domain)
	if _, err := mtls.NewServerTLSConfig(mtls.Config{CertFile: f.cert, KeyFile: f.key, CAFile: f.ca}); err == nil {
		t.Fatal("AllowedPeers なしで作れてしまった")
	}
	if _, err := mtls.NewServerTLSConfig(mtls.Config{CertFile: f.cert, KeyFile: f.key, CAFile: f.ca, AllowAnyPeer: true}); err != nil {
		t.Fatal(err)
	}
}

func TestSourceReloads(t *testing.T) {
	dir := t.TempDir()
	iss := testca.NewIssuer(t, testca.Domain)
	f := writeLeaf(t, iss, dir, "api."+testca.Domain)
	src, err := mtls.NewSource(f.cert, f.key, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := src.Certificate().Leaf.SerialNumber

	// 鍵だけ書き換わった途中の状態では、直前の証明書を使い続ける。
	otherKey, _ := pki.GenerateKey(pki.KeyECDSAP256)
	otherPEM, _ := pki.MarshalPrivateKeyPEM(otherKey)
	if err := pki.WriteFileAtomic(f.key, otherPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	bump(t, f.key)
	src.Reload()
	if got := src.Certificate().Leaf.SerialNumber; got.Cmp(first) != 0 {
		t.Fatal("対応しない鍵で証明書が差し替わった")
	}

	// 証明書と鍵がそろえば新しいものに切り替わる。
	f2 := writeLeaf(t, iss, dir, "api."+testca.Domain)
	bump(t, f2.cert)
	bump(t, f2.key)
	src.Reload()
	if got := src.Certificate().Leaf.SerialNumber; got.Cmp(first) == 0 {
		t.Fatal("更新後も古い証明書のまま")
	}
}

func bump(t *testing.T, path string) {
	t.Helper()
	next := time.Now().Add(time.Duration(len(path)) * time.Millisecond).Add(time.Second)
	if err := os.Chtimes(path, next, next); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPeerPatterns(t *testing.T) {
	_, err := mtls.NewClientTLSConfig(mtls.Config{CertFile: "x", KeyFile: "y", CAFile: "z", AllowedPeers: []string{"a.*.example.com"}})
	if err == nil || !strings.Contains(err.Error(), "AllowedPeers") {
		t.Fatalf("不正なパターンを受け付けた: %v", err)
	}
}
