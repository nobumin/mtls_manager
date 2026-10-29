package mtls_test

import (
	"crypto/x509"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobumin/mtls_manager/internal/federation"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/testca"
	"github.com/nobumin/mtls_manager/mtls"
)

const (
	domainA = "a.example.com"
	domainB = "b.example.net"
)

// writeBundle は signer（自分の中間 CA）で署名したトラストバンドルを書く。
func writeBundle(t *testing.T, path string, signer *pki.Issuer, seq uint64, expires time.Time, partners ...federation.BundlePartner) {
	t.Helper()
	now := time.Now()
	b := &federation.Bundle{
		Format: federation.BundleFormat, Epoch: "test", Seq: seq, IssuedAt: now.Add(-time.Minute), Expires: expires,
		OwnRoots: []string{federation.Fingerprint(signer.Root)}, Partners: partners,
	}
	compact, err := federation.Sign(b, signer.Cert, signer.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteFileAtomic(path, []byte(compact+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func partner(id string, root *x509.Certificate, domains ...string) federation.BundlePartner {
	return federation.BundlePartner{ID: id, RootCert: string(pki.EncodeCertsPEM(root)), RootSHA256: federation.Fingerprint(root), Domains: domains}
}

func fedClient(t *testing.T, f files, bundle, serverName string) *http.Client {
	t.Helper()
	cfg, err := mtls.NewClientTLSConfig(mtls.Config{CertFile: f.cert, KeyFile: f.key, CAFile: f.ca, TrustBundleFile: bundle})
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerName = serverName
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

func get(c *http.Client, addr string) error {
	res, err := c.Get("https://" + addr + "/")
	if err != nil {
		return err
	}
	res.Body.Close()
	return nil
}

// A 社のサーバと B 社のクライアントが、別々のルート CA のまま、連携で mTLS でつながる。
func TestFederatedMutualTLS(t *testing.T) {
	a := testca.NewIssuer(t, domainA)
	b := testca.NewIssuer(t, domainB)
	c := testca.NewIssuer(t, "c.example.org") // 連携していない第三者
	dirA, dirB, dirC := t.TempDir(), t.TempDir(), t.TempDir()
	srvA := writeLeaf(t, a, dirA, "api."+domainA)
	ownA := writeLeaf(t, a, dirA, "app."+domainA)
	cliB := writeLeaf(t, b, dirB, "web1."+domainB)
	cliC := writeLeaf(t, c, dirC, "web1.c.example.org")
	bundleA := filepath.Join(dirA, "trust-bundle.jws")
	bundleB := filepath.Join(dirB, "trust-bundle.jws")
	writeBundle(t, bundleA, a, 1, time.Now().Add(time.Hour), partner("b-corp", b.Root, domainB))
	writeBundle(t, bundleB, b, 1, time.Now().Add(time.Hour), partner("a-corp", a.Root, domainA))

	cfg, err := mtls.NewServerTLSConfig(mtls.Config{
		CertFile: srvA.cert, KeyFile: srvA.key, CAFile: srvA.ca, TrustBundleFile: bundleA,
		AllowedPeers: []string{"web1." + domainB, "web1.c.example.org", "app." + domainA}, ReloadInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, cfg)

	// B 社のクライアント（B のルートで、A のバンドルの範囲の内）は通る。クライアント側も A のサーバを連携で検証する。
	if err := get(fedClient(t, cliB, bundleB, "api."+domainA), addr); err != nil {
		t.Fatalf("連携先から接続できない: %v", err)
	}
	// 自分の組織のクライアントは、これまでどおり通る。
	if err := get(fedClient(t, ownA, bundleA, "api."+domainA), addr); err != nil {
		t.Fatalf("自分の組織から接続できない: %v", err)
	}
	// 連携していない CA の証明書は通らない（AllowedPeers に名前があっても）。
	if err := get(fedClient(t, cliC, filepath.Join(dirC, "none.jws"), "api."+domainA), addr); err == nil {
		t.Error("連携していない CA の証明書で接続できた")
	}
	// バンドルを持たない（連携先を信頼しない）クライアントは、A のサーバを検証できない。
	if err := get(client(t, cliB, "api."+domainA), addr); err == nil {
		t.Error("連携していないクライアントが A のサーバを信頼した")
	}

	// 範囲を狭めると（api.b.example.net だけ）、web1.b.example.net は通らない。
	writeBundle(t, bundleA, a, 2, time.Now().Add(time.Hour), partner("b-corp", b.Root, "api."+domainB))
	time.Sleep(50 * time.Millisecond)
	if err := get(fedClient(t, cliB, bundleB, "api."+domainA), addr); err == nil {
		t.Error("範囲の外の名前で接続できた")
	}
	// 停止（バンドルから外す）と通らない。自分の組織は通る。
	writeBundle(t, bundleA, a, 3, time.Now().Add(time.Hour))
	time.Sleep(50 * time.Millisecond)
	if err := get(fedClient(t, cliB, bundleB, "api."+domainA), addr); err == nil {
		t.Error("停止した連携先から接続できた")
	}
	if err := get(fedClient(t, ownA, bundleA, "api."+domainA), addr); err != nil {
		t.Errorf("停止の後、自分の組織から接続できない: %v", err)
	}
}

// バンドルの有効期限が切れたら連携先だけを外し、自分の組織の通信は続ける。
func TestFederationExpiredBundle(t *testing.T) {
	a := testca.NewIssuer(t, domainA)
	b := testca.NewIssuer(t, domainB)
	dirA, dirB := t.TempDir(), t.TempDir()
	srvA := writeLeaf(t, a, dirA, "api."+domainA)
	ownA := writeLeaf(t, a, dirA, "app."+domainA)
	cliB := writeLeaf(t, b, dirB, "web1."+domainB)
	bundleA, bundleB := filepath.Join(dirA, "b.jws"), filepath.Join(dirB, "b.jws")
	writeBundle(t, bundleA, a, 1, time.Now().Add(-time.Second), partner("b-corp", b.Root, domainB))
	writeBundle(t, bundleB, b, 1, time.Now().Add(time.Hour), partner("a-corp", a.Root, domainA))
	cfg, err := mtls.NewServerTLSConfig(mtls.Config{CertFile: srvA.cert, KeyFile: srvA.key, CAFile: srvA.ca, TrustBundleFile: bundleA, AllowedPeers: []string{"app." + domainA, "web1." + domainB}})
	if err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, cfg)
	if err := get(fedClient(t, cliB, bundleB, "api."+domainA), addr); err == nil {
		t.Error("期限切れのバンドルの連携先から接続できた")
	}
	if err := get(fedClient(t, ownA, bundleA, "api."+domainA), addr); err != nil {
		t.Errorf("期限切れのバンドルで、自分の組織の通信まで止まった: %v", err)
	}
}

// 自分のルートと異なる CA が署名したバンドル（CA サーバのすり替え等）や、自分の範囲と重なる連携先は使わない。
func TestFederationRejectsBadBundles(t *testing.T) {
	a := testca.NewIssuer(t, domainA)
	evil := testca.NewIssuer(t, "evil.example.org")
	dirA, dirE := t.TempDir(), t.TempDir()
	srvA := writeLeaf(t, a, dirA, "api."+domainA)
	cliE := writeLeaf(t, evil, dirE, "x.evil.example.org")
	bundleE := filepath.Join(dirE, "e.jws")
	writeBundle(t, bundleE, evil, 1, time.Now().Add(time.Hour), partner("a-corp", a.Root, domainA))
	for name, write := range map[string]func(path string){
		// 別の CA が署名した（自分のルートにつながらない）。
		"別の CA の署名": func(p string) {
			writeBundle(t, p, evil, 1, time.Now().Add(time.Hour), partner("evil", evil.Root, "evil.example.org"))
		},
		// 自分の範囲と重なる連携先（乗っ取られた CA が署名した想定）。
		"自分の範囲と重なる": func(p string) {
			writeBundle(t, p, a, 1, time.Now().Add(time.Hour), partner("evil", evil.Root, "evil.example.org", "x."+domainA))
		},
	} {
		t.Run(name, func(t *testing.T) {
			bundle := filepath.Join(t.TempDir(), "a.jws")
			write(bundle)
			cfg, err := mtls.NewServerTLSConfig(mtls.Config{CertFile: srvA.cert, KeyFile: srvA.key, CAFile: srvA.ca, TrustBundleFile: bundle, AllowedPeers: []string{"x.evil.example.org"}})
			if err != nil {
				t.Fatal(err)
			}
			addr := startServer(t, cfg)
			if err := get(fedClient(t, cliE, bundleE, "api."+domainA), addr); err == nil {
				t.Error("不正なバンドルの連携先から接続できた")
			}
		})
	}
}

// 名前制約の無い中間 CA（自分の範囲が決まらない）では、連携先を 1 つも信頼しない。
func TestFederationRequiresNameConstraints(t *testing.T) {
	a := testca.NewIssuer(t) // 名前制約なし
	b := testca.NewIssuer(t, domainB)
	dirA, dirB := t.TempDir(), t.TempDir()
	srvA := writeLeaf(t, a, dirA, "api."+domainA)
	cliB := writeLeaf(t, b, dirB, "web1."+domainB)
	bundleA, bundleB := filepath.Join(dirA, "b.jws"), filepath.Join(dirB, "b.jws")
	writeBundle(t, bundleA, a, 1, time.Now().Add(time.Hour), partner("b-corp", b.Root, domainB))
	writeBundle(t, bundleB, b, 1, time.Now().Add(time.Hour), partner("a-corp", a.Root, domainA))
	cfg, err := mtls.NewServerTLSConfig(mtls.Config{CertFile: srvA.cert, KeyFile: srvA.key, CAFile: srvA.ca, TrustBundleFile: bundleA, AllowedPeers: []string{"web1." + domainB}})
	if err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, cfg)
	if err := get(fedClient(t, cliB, bundleB, "api."+domainA), addr); err == nil {
		t.Error("名前制約の無い中間 CA で連携先を信頼した")
	}
}

// 連携版のクライアントは、IP アドレスでの接続（ホスト名を確かめられない）を拒否する（実装 1）。
func TestFederatedClientRejectsIPConnection(t *testing.T) {
	a := testca.NewIssuer(t, domainA)
	b := testca.NewIssuer(t, domainB)
	dirA, dirB := t.TempDir(), t.TempDir()
	cliA := writeLeaf(t, a, dirA, "app."+domainA)
	srvB := writeLeaf(t, b, dirB, "web1."+domainB) // IP SAN なし
	bundleA, bundleB := filepath.Join(dirA, "b.jws"), filepath.Join(dirB, "a.jws")
	writeBundle(t, bundleA, a, 1, time.Now().Add(time.Hour), partner("b-corp", b.Root, domainB))
	writeBundle(t, bundleB, b, 1, time.Now().Add(time.Hour), partner("a-corp", a.Root, domainA))
	cfg, err := mtls.NewServerTLSConfig(mtls.Config{CertFile: srvB.cert, KeyFile: srvB.key, CAFile: srvB.ca, TrustBundleFile: bundleB, AllowedPeers: []string{"app." + domainA}})
	if err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, cfg)
	// IP アドレスで接続すると、サーバ名が空になるので拒否する（従来のクライアントと同じく通さない）。
	err = get(fedClient(t, cliA, bundleA, ""), addr)
	if err == nil || !strings.Contains(err.Error(), "ホスト名") {
		t.Errorf("IP アドレスでの接続を拒否しない: %v", err)
	}
	// 別のホスト名を名乗る接続も拒否する（ホスト名を確かめている）。
	if err := get(fedClient(t, cliA, bundleA, "api."+domainA), addr); err == nil {
		t.Error("証明書と違うホスト名で接続できた")
	}
	// ホスト名で接続すれば通る。
	if err := get(fedClient(t, cliA, bundleA, "web1."+domainB), addr); err != nil {
		t.Errorf("ホスト名で接続できない: %v", err)
	}
}

// AllowAnyPeer は自分の組織の相手にだけ効き、連携先の相手は AllowedPeers に一致しなければ拒否する（実装 2）。
func TestAllowAnyPeerDoesNotExtendToPartners(t *testing.T) {
	a := testca.NewIssuer(t, domainA)
	b := testca.NewIssuer(t, domainB)
	dirA, dirB := t.TempDir(), t.TempDir()
	srvA := writeLeaf(t, a, dirA, "api."+domainA)
	ownA := writeLeaf(t, a, dirA, "app."+domainA)
	cliB := writeLeaf(t, b, dirB, "web1."+domainB)
	bundleA, bundleB := filepath.Join(dirA, "b.jws"), filepath.Join(dirB, "a.jws")
	writeBundle(t, bundleA, a, 1, time.Now().Add(time.Hour), partner("b-corp", b.Root, domainB))
	writeBundle(t, bundleB, b, 1, time.Now().Add(time.Hour), partner("a-corp", a.Root, domainA))
	cfg, err := mtls.NewServerTLSConfig(mtls.Config{CertFile: srvA.cert, KeyFile: srvA.key, CAFile: srvA.ca, TrustBundleFile: bundleA, AllowAnyPeer: true})
	if err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, cfg)
	if err := get(fedClient(t, ownA, bundleA, "api."+domainA), addr); err != nil {
		t.Errorf("自分の組織の相手を AllowAnyPeer で受け入れない: %v", err)
	}
	if err := get(fedClient(t, cliB, bundleB, "api."+domainA), addr); err == nil {
		t.Error("AllowAnyPeer で連携先の相手を受け入れた")
	}
}

// ファイルを古いバンドル（停止の前のもの）に戻されても、受け入れない（実装 3）。
func TestLibraryRejectsBundleRollback(t *testing.T) {
	a := testca.NewIssuer(t, domainA)
	b := testca.NewIssuer(t, domainB)
	dirA, dirB := t.TempDir(), t.TempDir()
	srvA := writeLeaf(t, a, dirA, "api."+domainA)
	cliB := writeLeaf(t, b, dirB, "web1."+domainB)
	bundleA, bundleB := filepath.Join(dirA, "b.jws"), filepath.Join(dirB, "a.jws")
	writeBundle(t, bundleB, b, 1, time.Now().Add(time.Hour), partner("a-corp", a.Root, domainA))
	// 停止した後のバンドル（連番 2、連携先なし）。
	writeBundle(t, bundleA, a, 2, time.Now().Add(time.Hour))
	cfg, err := mtls.NewServerTLSConfig(mtls.Config{
		CertFile: srvA.cert, KeyFile: srvA.key, CAFile: srvA.ca, TrustBundleFile: bundleA,
		AllowedPeers: []string{"web1." + domainB}, ReloadInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, cfg)
	// 停止の前のバンドル（連番 1、連携先あり）に戻す。
	writeBundle(t, bundleA, a, 1, time.Now().Add(time.Hour), partner("b-corp", b.Root, domainB))
	time.Sleep(50 * time.Millisecond)
	if err := get(fedClient(t, cliB, bundleB, "api."+domainA), addr); err == nil {
		t.Error("古いバンドルに戻されて、停止した連携先を再び信頼した")
	}
}

// 連携先のルート CA の入れ替え中は、新旧どちらのルートの証明書も受け入れ、古いルートを外すと新しいほうだけになる。
func TestFederationRootRotation(t *testing.T) {
	a := testca.NewIssuer(t, domainA)
	oldB := testca.NewIssuer(t, domainB)
	newB := testca.NewIssuer(t, domainB)
	dirA, dirOld, dirNew := t.TempDir(), t.TempDir(), t.TempDir()
	srvA := writeLeaf(t, a, dirA, "api."+domainA)
	cliOld := writeLeaf(t, oldB, dirOld, "web1."+domainB)
	cliNew := writeLeaf(t, newB, dirNew, "web1."+domainB)
	bundleA := filepath.Join(dirA, "b.jws")
	bundleOld, bundleNew := filepath.Join(dirOld, "a.jws"), filepath.Join(dirNew, "a.jws")
	writeBundle(t, bundleOld, oldB, 1, time.Now().Add(time.Hour), partner("a-corp", a.Root, domainA))
	writeBundle(t, bundleNew, newB, 1, time.Now().Add(time.Hour), partner("a-corp", a.Root, domainA))

	rotating := partner("b-corp", oldB.Root, domainB)
	rotating.NextRootCert, rotating.NextRootSHA256 = string(pki.EncodeCertsPEM(newB.Root)), federation.Fingerprint(newB.Root)
	writeBundle(t, bundleA, a, 1, time.Now().Add(time.Hour), rotating)
	cfg, err := mtls.NewServerTLSConfig(mtls.Config{
		CertFile: srvA.cert, KeyFile: srvA.key, CAFile: srvA.ca, TrustBundleFile: bundleA,
		AllowedPeers: []string{"web1." + domainB}, ReloadInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, cfg)
	for name, c := range map[string]*http.Client{
		"古いルート":  fedClient(t, cliOld, bundleOld, "api."+domainA),
		"新しいルート": fedClient(t, cliNew, bundleNew, "api."+domainA),
	} {
		if err := get(c, addr); err != nil {
			t.Errorf("入れ替え中に%sの証明書で接続できない: %v", name, err)
		}
	}
	// 古いルートを外す（新しいルートだけのバンドル）。
	writeBundle(t, bundleA, a, 2, time.Now().Add(time.Hour), partner("b-corp", newB.Root, domainB))
	time.Sleep(50 * time.Millisecond)
	if err := get(fedClient(t, cliOld, bundleOld, "api."+domainA), addr); err == nil {
		t.Error("古いルートを外した後も、古いルートの証明書で接続できた")
	}
	if err := get(fedClient(t, cliNew, bundleNew, "api."+domainA), addr); err != nil {
		t.Errorf("古いルートを外した後、新しいルートの証明書で接続できない: %v", err)
	}
}
