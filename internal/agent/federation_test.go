package agent

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/federation"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/testca"
)

const partnerDomain = "b.example.net"

// startFederatedCA は連携版を有効にした CA を起動し、連携先 b-corp を 2 人で承認する。
func startFederatedCA(t *testing.T) (*testca.CA, string, *pki.Issuer) {
	t.Helper()
	fedFile := filepath.Join(t.TempDir(), "federation.json")
	ca := testca.Start(t, func(c *config.CA) { c.Federation.File = fedFile })
	b := testca.NewIssuer(t, partnerDomain)
	rec, err := federation.NewRecord(b.Root, []string{partnerDomain}, "B 社", nil)
	if err != nil {
		t.Fatal(err)
	}
	fp := federation.Fingerprint(b.Root)
	own := []string{testca.Domain}
	now := time.Now()
	if err := federation.Update(fedFile, func(f *federation.File) error {
		if err := f.Import("b-corp", rec, b.Root, now, "alice"); err != nil {
			return err
		}
		if err := f.Request("b-corp", federation.RequestOptions{Fingerprint: fp, ComparedWith: "電話", By: "alice"}, own, now); err != nil {
			return err
		}
		return f.Approve("b-corp", fp, "bob", own, now)
	}); err != nil {
		t.Fatal(err)
	}
	return ca, fedFile, b
}

func TestSyncBundle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ca, fedFile, b := startFederatedCA(t)
	kid, _, hmacB64 := ca.AddEAB(t, web1)
	cfg := newConfig(t, ca, kid, hmacB64)
	listen := freeAddr(t)
	cfg.Challenge = config.AgentChallenge{Type: config.ChallengeHTTP01, Listen: listen}
	dir := filepath.Dir(cfg.Output.Cert)
	cfg.Output.TrustBundle = filepath.Join(dir, "trust-bundle.jws")
	cfg.Output.FederationDir = filepath.Join(dir, "federation")
	marker := filepath.Join(t.TempDir(), "bundle-hook")
	cfg.Hooks.PostBundle = []string{"sh", "-c", "echo x >> " + marker}
	ca.SetTarget(config.ChallengeHTTP01, listen)
	a := newAgent(t, cfg, ca)

	// 証明書を取得する前は、自分の中間 CA が分からないので取得しない。
	if err := a.SyncBundle(ctx, time.Now()); err == nil {
		t.Error("証明書の取得の前にバンドルを受け入れた")
	}
	if err := a.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.SyncBundle(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	pemPath := filepath.Join(cfg.Output.FederationDir, "b-corp.pem")
	certs, err := pki.LoadCerts(pemPath)
	if err != nil || !certs[0].Equal(b.Root) {
		t.Fatalf("連携先の PEM が無い: %v", err)
	}
	if d, _ := os.ReadFile(filepath.Join(cfg.Output.FederationDir, "b-corp.domains")); strings.TrimSpace(string(d)) != partnerDomain {
		t.Errorf("範囲のファイル: %q", d)
	}
	if data, err := os.ReadFile(cfg.Output.TrustBundle); err != nil || len(data) < 100 {
		t.Fatal("トラストバンドルが書かれていない")
	}
	if n := countLines(t, marker); n != 1 {
		t.Errorf("更新後のコマンドの実行回数 = %d", n)
	}
	if p := a.BundleProblem(time.Now()); p != "" {
		t.Errorf("問題があると判断した: %s", p)
	}
	// 変化が無ければ書き直さず、コマンドも実行しない（ETag）。
	if err := a.SyncBundle(ctx, time.Now()); err != nil || countLines(t, marker) != 1 {
		t.Errorf("変化が無いのに更新した: %v", err)
	}

	// 停止すると、PEM は消さずに「どこにもつながらない PEM」に置き換わる。
	if err := federation.Update(fedFile, func(f *federation.File) error { return f.Suspend("b-corp", "carol", "", time.Now()) }); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := a.SyncBundle(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	certs, err = pki.LoadCerts(pemPath)
	if err != nil || certs[0].Equal(b.Root) {
		t.Fatalf("停止した連携先の PEM が置き換わっていない: %v", err)
	}
	if d, _ := os.ReadFile(filepath.Join(cfg.Output.FederationDir, "b-corp.domains")); len(d) != 0 {
		t.Errorf("停止した連携先の範囲のファイルが空でない: %q", d)
	}
	if n := countLines(t, marker); n != 2 {
		t.Errorf("停止の後、更新後のコマンドの実行回数 = %d", n)
	}
}

// 古いバンドルの再送を拒否し、エポックが変わったら発行時刻の新しさで受け入れる。
func TestBundleReplayAndEpoch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ca, _, _ := startFederatedCA(t)
	kid, _, hmacB64 := ca.AddEAB(t, web1)
	cfg := newConfig(t, ca, kid, hmacB64)
	listen := freeAddr(t)
	cfg.Challenge = config.AgentChallenge{Type: config.ChallengeHTTP01, Listen: listen}
	cfg.Output.TrustBundle = filepath.Join(t.TempDir(), "trust-bundle.jws")
	ca.SetTarget(config.ChallengeHTTP01, listen)
	a := newAgent(t, cfg, ca)
	if err := a.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.SyncBundle(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	st := a.loadBundleState()

	// 手元のほうが新しい（同じエポックで連番が大きい）と、CA のバンドルを古いとみなして拒否する。
	newer := *st
	newer.Seq = st.Seq + 10
	if err := a.saveBundleState(&newer); err != nil {
		t.Fatal(err)
	}
	a.fed.etag = ""
	if err := a.SyncBundle(ctx, time.Now()); err == nil || !strings.Contains(err.Error(), "古い") {
		t.Errorf("古いバンドルを受け入れた: %v", err)
	}
	// エポックが違い、発行時刻が手元より新しくなければ拒否する。
	other := *st
	other.Epoch, other.IssuedAt = "other", st.IssuedAt.Add(time.Hour)
	_ = a.saveBundleState(&other)
	if err := a.SyncBundle(ctx, time.Now()); err == nil {
		t.Error("発行時刻の古い、エポックの違うバンドルを受け入れた")
	}
	// エポックが違い、発行時刻が新しければ受け入れる（CA の再起動・復旧）。
	other.IssuedAt = st.IssuedAt.Add(-time.Hour)
	_ = a.saveBundleState(&other)
	if err := a.SyncBundle(ctx, time.Now()); err != nil {
		t.Errorf("エポックの変わったバンドルを受け入れない: %v", err)
	}
	if got := a.loadBundleState(); got.Epoch != st.Epoch {
		t.Errorf("エポックが更新されていない: %s", got.Epoch)
	}
}

// バンドルの期限が切れたら連携先をすべて外し、check で分かる。更新後のコマンドの失敗も check で分かる。
func TestBundleExpiryAndHookFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ca, _, b := startFederatedCA(t)
	kid, _, hmacB64 := ca.AddEAB(t, web1)
	cfg := newConfig(t, ca, kid, hmacB64)
	listen := freeAddr(t)
	cfg.Challenge = config.AgentChallenge{Type: config.ChallengeHTTP01, Listen: listen}
	cfg.Output.FederationDir = filepath.Join(t.TempDir(), "federation")
	cfg.Hooks.PostBundle = []string{"false"}
	ca.SetTarget(config.ChallengeHTTP01, listen)
	a := newAgent(t, cfg, ca)
	if err := a.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.SyncBundle(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if p := a.BundleProblem(time.Now()); !strings.Contains(p, "コマンドが失敗") {
		t.Errorf("更新後のコマンドの失敗が check に出ない: %q", p)
	}
	// 失敗したコマンドは、指数バックオフの待ちの間は再試行しない。
	next := a.fed.hookNext
	if next.IsZero() || time.Until(next) < 20*time.Second {
		t.Errorf("再試行の待ちが短い: %v", time.Until(next))
	}

	// 期限切れ（CA に届かないまま有効期限を過ぎた）。
	later := time.Now().Add(federation.DefaultBundleValidity + time.Minute)
	a.http.Transport = brokenTransport{}
	_ = a.SyncBundle(ctx, later)
	certs, err := pki.LoadCerts(filepath.Join(cfg.Output.FederationDir, "b-corp.pem"))
	if err != nil || certs[0].Equal(b.Root) {
		t.Fatalf("期限切れで連携先が外れていない: %v", err)
	}
	if p := a.BundleProblem(later); !strings.Contains(p, "有効期限が切れ") {
		t.Errorf("期限切れが check に出ない: %q", p)
	}
}

type brokenTransport struct{}

func (brokenTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("CA に届かない")
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(data), "\n")
}
