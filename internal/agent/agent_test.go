package agent

import (
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/testca"
)

const web1 = "web1." + testca.Domain

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func newConfig(t *testing.T, ca *testca.CA, kid, hmacB64 string) *config.Agent {
	t.Helper()
	dir := t.TempDir()
	hmacFile := filepath.Join(dir, "eab.hmac")
	if err := os.WriteFile(hmacFile, []byte(hmacB64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Agent{
		CAURL:      ca.DirectoryURL,
		CARoot:     ca.RootFile,
		AccountKey: filepath.Join(dir, "state", "account.key"),
		EAB:        config.AgentEAB{KID: kid, HMACFile: hmacFile},
		Names:      []string{web1},
		Output: config.AgentOutput{
			Cert: filepath.Join(dir, "tls", "cert.pem"), Key: filepath.Join(dir, "tls", "key.pem"),
			Chain: filepath.Join(dir, "tls", "chain.pem"), Fullchain: filepath.Join(dir, "tls", "fullchain.pem"),
			CA: filepath.Join(dir, "tls", "ca.pem"),
		},
	}
	return cfg
}

func newAgent(t *testing.T, cfg *config.Agent, ca *testca.CA) *Agent {
	t.Helper()
	if err := cfg.Complete(); err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// テストでは CA のホスト名を 127.0.0.1 に向ける。
	a.http.Transport.(*http.Transport).DialContext = ca.DialContext
	return a
}

func TestObtainHTTP01AndCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, _, hmacB64 := ca.AddEAB(t, web1)
	cfg := newConfig(t, ca, kid, hmacB64)
	listen := freeAddr(t)
	cfg.Challenge = config.AgentChallenge{Type: config.ChallengeHTTP01, Listen: listen}
	marker := filepath.Join(t.TempDir(), "hook-ran")
	cfg.Hooks.PostRenew = []string{"touch", marker}
	ca.SetTarget(config.ChallengeHTTP01, listen)
	a := newAgent(t, cfg, ca)

	if st := a.Check(time.Now()); !st.NeedsRenewal() {
		t.Fatal("証明書が無いのに更新不要と判断した")
	}
	if err := a.Obtain(ctx); err != nil {
		t.Fatalf("Obtain: %v", err)
	}
	st := a.Check(time.Now())
	if st.NeedsRenewal() {
		t.Fatalf("取得直後なのに更新が必要: %s", st.Reason)
	}
	// 有効期間の 2/3 を過ぎたら更新が必要になる。
	if later := a.Check(st.RenewAt.Add(time.Second)); !later.NeedsRenewal() {
		t.Fatal("更新時期を過ぎても更新不要と判断した")
	}

	fi, err := os.Stat(cfg.Output.Key)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("秘密鍵の権限 = %04o", fi.Mode().Perm())
	}
	if fi, err := os.Stat(cfg.AccountKey); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("アカウント鍵: %v", err)
	}
	full, err := pki.LoadCerts(cfg.Output.Fullchain)
	if err != nil || len(full) != 2 {
		t.Fatalf("fullchain: %d 枚, %v", len(full), err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("更新後のコマンドが実行されていない")
	}

	// 2 回目は登録済みのアカウントで取得する（EAB の HMAC が無くてもよい）。
	cfg.EAB.HMACFile = ""
	b := newAgent(t, cfg, ca)
	if err := b.Obtain(ctx); err != nil {
		t.Fatalf("2 回目の Obtain: %v", err)
	}
}

func TestObtainTLSALPN01(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, _, hmacB64 := ca.AddEAB(t, web1)
	cfg := newConfig(t, ca, kid, hmacB64)
	// ルート CA の入れ替え中を模して、無関係な新しいルートを先頭に並べる。
	other := testca.NewIssuer(t)
	bundle := append(pki.EncodeCertsPEM(other.Root), pki.EncodeCertsPEM(ca.Issuer.Root)...)
	cfg.CARoot = filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(cfg.CARoot, bundle, 0o644); err != nil {
		t.Fatal(err)
	}
	listen := freeAddr(t)
	cfg.Challenge = config.AgentChallenge{Type: config.ChallengeTLSALPN01, Listen: listen}
	ca.SetTarget(config.ChallengeTLSALPN01, listen)
	a := newAgent(t, cfg, ca)
	if err := a.Obtain(ctx); err != nil {
		t.Fatalf("Obtain: %v", err)
	}
	if roots, err := pki.LoadCerts(cfg.Output.CA); err != nil || len(roots) != 2 {
		t.Errorf("output.ca に新旧のルートが書かれていない: %d 枚, %v", len(roots), err)
	}
}

func TestObtainWebroot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, _, hmacB64 := ca.AddEAB(t, web1)
	cfg := newConfig(t, ca, kid, hmacB64)
	webroot := t.TempDir()
	cfg.Challenge = config.AgentChallenge{Type: config.ChallengeHTTP01, Webroot: webroot}

	// 既存の Web サーバを模す。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.FileServer(http.Dir(webroot))}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	ca.SetTarget(config.ChallengeHTTP01, ln.Addr().String())

	a := newAgent(t, cfg, ca)
	if err := a.Obtain(ctx); err != nil {
		t.Fatalf("Obtain: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(webroot, ".well-known", "acme-challenge"))
	if len(entries) != 0 {
		t.Errorf("webroot の応答ファイルが残っている: %d 個", len(entries))
	}
}

func TestObtainFailsWithoutEAB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	cfg := newConfig(t, ca, "", "")
	cfg.EAB = config.AgentEAB{}
	cfg.Challenge = config.AgentChallenge{Listen: freeAddr(t)}
	a := newAgent(t, cfg, ca)
	err := a.Obtain(ctx)
	if err == nil || !strings.Contains(err.Error(), "eab.kid") {
		t.Fatalf("EAB なしの初回登録のエラーが分かりにくい: %v", err)
	}
}

func TestRunRenewsOnRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, _, hmacB64 := ca.AddEAB(t, web1)
	cfg := newConfig(t, ca, kid, hmacB64)
	listen := freeAddr(t)
	cfg.Challenge = config.AgentChallenge{Type: config.ChallengeHTTP01, Listen: listen}
	cfg.Renew.CheckInterval = config.Duration(time.Second)
	ca.SetTarget(config.ChallengeHTTP01, listen)
	a := newAgent(t, cfg, ca)

	renew := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { a.Run(ctx, renew); close(done) }()

	first := waitSerial(t, ctx, a, "")
	renew <- struct{}{}
	waitSerial(t, ctx, a, first)
	cancel()
	<-done
}

// waitSerial はシリアルが prev 以外になるまで待つ。
func waitSerial(t *testing.T, ctx context.Context, a *Agent, prev string) string {
	t.Helper()
	for {
		if st := a.Check(time.Now()); st.Exists && st.Serial != prev && !st.NeedsRenewal() {
			return st.Serial
		}
		select {
		case <-ctx.Done():
			t.Fatal("証明書が更新されない")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// chain / fullchain を出力しない設定でも、取得直後に「更新が必要」と判断しない（再発行の繰り返しを防ぐ）。
func TestCheckWithoutChainOutputs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, _, hmacB64 := ca.AddEAB(t, web1)
	cfg := newConfig(t, ca, kid, hmacB64)
	cfg.Output.Chain, cfg.Output.Fullchain, cfg.Output.CA = "", "", ""
	listen := freeAddr(t)
	cfg.Challenge = config.AgentChallenge{Type: config.ChallengeHTTP01, Listen: listen}
	ca.SetTarget(config.ChallengeHTTP01, listen)
	a := newAgent(t, cfg, ca)
	if err := a.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	if st := a.Check(time.Now()); st.NeedsRenewal() {
		t.Fatalf("取得直後なのに更新が必要: %s", st.Reason)
	}
}

// 有効期間が短く fraction が小さくても、更新時期は取得した時刻から数える。
func TestRenewAtCountsFromObtainedTime(t *testing.T) {
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(10 * time.Minute)}
	saved := &state{Serial: serialHex(leaf), ObtainedAt: now}
	if got := renewAt(leaf, saved, 0.1); !got.After(now) {
		t.Fatalf("更新時期 %v が取得時刻 %v より前", got, now)
	}
	// 別の証明書の記録なら NotBefore から数える。
	other := &state{Serial: "ff", ObtainedAt: now}
	if got := renewAt(leaf, other, 0.1); !got.Equal(leaf.NotBefore.Add(90 * time.Second)) {
		t.Fatalf("NotBefore から数えていない: %v", got)
	}
}

// CA がアカウントを受け付けなくなったら、使い回しのクライアントを捨てる（次の試行で確認し直す）。
func TestObtainResetsClientWhenAccountRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, _, hmacB64 := ca.AddEAB(t, web1)
	cfg := newConfig(t, ca, kid, hmacB64)
	listen := freeAddr(t)
	cfg.Challenge = config.AgentChallenge{Type: config.ChallengeHTTP01, Listen: listen}
	ca.SetTarget(config.ChallengeHTTP01, listen)
	a := newAgent(t, cfg, ca)
	if err := a.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.client.DeactivateReg(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Obtain(ctx); err == nil {
		t.Fatal("無効にしたアカウントで取得できた")
	}
	if a.client != nil {
		t.Fatal("アカウントを拒否されても、クライアントを使い回している")
	}
}
