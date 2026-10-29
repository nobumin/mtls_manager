package federation_test

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobumin/mtls_manager/internal/federation"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/testca"
)

const (
	domainA = "a.example.com"
	domainB = "b.example.net"
)

func TestNormalizeScope(t *testing.T) {
	for _, bad := range [][]string{nil, {"net"}, {"com"}, {"co.jp"}, {"bad name"}, {"*.example.net"}} {
		if _, err := federation.NormalizeScope(bad); err == nil {
			t.Errorf("%v: 受け付けた", bad)
		}
	}
	got, err := federation.NormalizeScope([]string{"B.Example.NET.", "b.example.net", "api.c.example.org"})
	if err != nil || len(got) != 2 || got[0] != "api.c.example.org" || got[1] != "b.example.net" {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestFingerprint(t *testing.T) {
	iss := testca.NewIssuer(t, domainA)
	fp := federation.Fingerprint(iss.Root)
	if len(fp) != 95 || strings.Count(fp, ":") != 31 {
		t.Fatalf("指紋の形 %q", fp)
	}
	flat := strings.ToLower(strings.ReplaceAll(fp, ":", ""))
	if !federation.FingerprintEqual(fp, flat) || federation.FingerprintEqual(fp, flat[:62]) {
		t.Error("書き方の違いの吸収、または長さの確認が効かない")
	}
}

func TestRecordRoundTrip(t *testing.T) {
	iss := testca.NewIssuer(t, domainB)
	rec, err := federation.NewRecord(iss.Root, []string{domainB}, "B 社", []string{"sec@b.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	data := mustJSON(t, rec)
	if _, root, err := federation.ParseRecord(data); err != nil || !root.Equal(iss.Root) {
		t.Fatalf("読み戻せない: %v", err)
	}
	// 指紋をすり替えたものは拒否する。
	rec.RootSHA256 = federation.Fingerprint(testca.NewIssuer(t, domainB).Root)
	if _, _, err := federation.ParseRecord(mustJSON(t, rec)); err == nil {
		t.Error("指紋の合わない連携情報を受け付けた")
	}
	// 中間 CA（ルートでない証明書）は受け付けない。
	rec2, _ := federation.NewRecord(iss.Root, []string{domainB}, "", nil)
	rec2.RootCert = string(pki.EncodeCertsPEM(iss.Cert))
	rec2.RootSHA256 = federation.Fingerprint(iss.Cert)
	if _, _, err := federation.ParseRecord(mustJSON(t, rec2)); err == nil {
		t.Error("自己署名でない証明書をルート CA として受け付けた")
	}
}

func TestValidateID(t *testing.T) {
	for _, ok := range []string{"b", "b-corp", "partner-01"} {
		if err := federation.ValidateID(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-b", "b-", "B", "../etc", "a/b", "a.b", strings.Repeat("a", 33)} {
		if federation.ValidateID(bad) == nil {
			t.Errorf("%q を受け付けた", bad)
		}
	}
}

// 取り込み → 申請（1 人目）→ 承認（2 人目）→ 停止 の流れと、その中での拒否。
func TestApprovalWorkflow(t *testing.T) {
	b := testca.NewIssuer(t, domainB)
	rec, _ := federation.NewRecord(b.Root, []string{domainB}, "B 社", nil)
	fp := federation.Fingerprint(b.Root)
	own := []string{domainA}
	now := time.Now()
	f := &federation.File{}

	if err := f.Import("../b", rec, b.Root, now, federation.ByCLI("alice")); err == nil {
		t.Error("不正な識別子で取り込めた")
	}
	if err := f.Import("b-corp", rec, b.Root, now, federation.ByCLI("alice")); err != nil {
		t.Fatal(err)
	}
	if err := f.Import("b-again", rec, b.Root, now, federation.ByCLI("alice")); err == nil {
		t.Error("同じルート CA を 2 回取り込めた")
	}
	// 承認待ちのままでは承認できない（申請が先）。
	if err := f.Approve("b-corp", fp, federation.ByCLI("bob"), own, now); err == nil {
		t.Error("申請の前に承認できた")
	}
	req := federation.RequestOptions{Fingerprint: fp, ComparedWith: "契約書記載の B 社 情報システム部、電話", By: federation.ByCLI("alice")}
	for name, o := range map[string]federation.RequestOptions{
		"指紋の一部だけ":     {Fingerprint: fp[:47], ComparedWith: req.ComparedWith, By: federation.ByCLI("alice")},
		"違う指紋":        {Fingerprint: federation.Fingerprint(testca.NewIssuer(t, domainB).Root), ComparedWith: req.ComparedWith, By: federation.ByCLI("alice")},
		"照合の相手なし":     {Fingerprint: fp, By: federation.ByCLI("alice")},
		"申告より広い範囲":    {Fingerprint: fp, ComparedWith: req.ComparedWith, Domains: []string{"example.net"}, By: federation.ByCLI("alice")},
		"自分の範囲と重なる範囲": {Fingerprint: fp, ComparedWith: req.ComparedWith, Domains: []string{"x." + domainA}, By: federation.ByCLI("alice")},
	} {
		if err := f.Request("b-corp", o, own, now); err == nil {
			t.Errorf("%s: 申請できた", name)
		}
	}
	// 自分の範囲と重なる申告は、そのままでは申請できない。
	f2 := &federation.File{}
	recOverlap, _ := federation.NewRecord(b.Root, []string{"b." + domainA}, "", nil)
	_ = f2.Import("x", recOverlap, b.Root, now, federation.ByCLI("alice"))
	if err := f2.Request("x", req, own, now); err == nil {
		t.Error("自分の範囲と重なる連携先を申請できた")
	}

	narrowed := req
	narrowed.Domains = []string{"api." + domainB}
	if err := f.Request("b-corp", narrowed, own, now); err != nil {
		t.Fatal(err)
	}
	if err := f.Approve("b-corp", fp, federation.ByCLI("alice"), own, now); err == nil {
		t.Error("申請者と同じ管理者が承認できた")
	}
	if err := f.Approve("b-corp", "00"+fp[2:], federation.ByCLI("bob"), own, now); err == nil {
		t.Error("違う指紋で承認できた")
	}
	if err := f.Approve("b-corp", fp, federation.ByCLI("bob"), own, now); err != nil {
		t.Fatal(err)
	}
	p := f.Find("b-corp")
	if p.State != federation.StateActive || len(p.Domains) != 1 || p.Domains[0] != "api."+domainB || p.ComparedWith == "" {
		t.Fatalf("承認後の状態が違う: %+v", p)
	}
	if err := f.Remove("b-corp"); err == nil {
		t.Error("有効な連携先を停止せずに消せた")
	}
	if err := f.Suspend("b-corp", federation.ByCLI("carol"), "連携先の侵害の疑い", now); err != nil || f.Find("b-corp").State != federation.StateSuspended {
		t.Fatalf("停止できない: %v", err)
	}
	if len(f.Find("b-corp").Events) != 4 {
		t.Errorf("操作の記録が %d 件", len(f.Find("b-corp").Events))
	}
	if err := f.Remove("b-corp"); err != nil {
		t.Fatal(err)
	}
}

func TestOwnScope(t *testing.T) {
	iss := testca.NewIssuer(t, domainA, "a.example.org")
	pool := x509.NewCertPool()
	pool.AddCert(iss.Root)
	if got, err := federation.OwnScope(iss.Cert, pool, nil); err != nil || len(got) != 2 {
		t.Fatalf("got %v %v", got, err)
	}
	if got, err := federation.OwnScope(iss.Cert, pool, []string{"x." + domainA}); err != nil || got[0] != "x."+domainA {
		t.Fatalf("狭められない: %v %v", got, err)
	}
	if _, err := federation.OwnScope(iss.Cert, pool, []string{"example.com"}); err == nil {
		t.Error("名前制約より広い範囲にできた")
	}
	noNC := testca.NewIssuer(t)
	pool2 := x509.NewCertPool()
	pool2.AddCert(noNC.Root)
	if _, err := federation.OwnScope(noNC.Cert, pool2, nil); err == nil {
		t.Error("名前制約の無い中間 CA で範囲が決まった")
	}
	if _, err := federation.OwnScope(noNC.Cert, pool, nil); err == nil {
		t.Error("自分のルートにつながらない中間 CA を受け付けた")
	}
}

func TestCheckPeer(t *testing.T) {
	b := testca.NewIssuer(t, domainB)
	key, _ := pki.GenerateKey(pki.KeyECDSAP256)
	scope := []string{domainB}
	ok, _ := b.IssueLeaf(key.Public(), []string{"web1." + domainB}, time.Hour)
	if err := federation.CheckPeer(ok, scope); err != nil {
		t.Fatal(err)
	}
	outside := *ok
	outside.DNSNames = []string{"web1." + domainB, "web1." + domainA}
	wildcard := *ok
	wildcard.DNSNames = []string{"*." + domainB}
	noName := *ok
	noName.DNSNames = nil
	withIP := *ok
	withIP.IPAddresses = []net.IP{net.ParseIP("10.0.0.1")}
	for name, c := range map[string]*x509.Certificate{"範囲の外の名前を含む": &outside, "ワイルドカード": &wildcard, "DNS 名なし": &noName, "IP アドレス": &withIP} {
		if federation.CheckPeer(c, scope) == nil {
			t.Errorf("%s: 受け付けた", name)
		}
	}
}

// バンドルの作成（CA）と検証（mtls-agent・ライブラリ）。
func TestBundleSignAndVerify(t *testing.T) {
	a := testca.NewIssuer(t, domainA)
	b := testca.NewIssuer(t, domainB)
	dir := t.TempDir()
	path := filepath.Join(dir, "federation.json")
	approve(t, path, "b-corp", b.Root, []string{domainB}, []string{domainA})

	store, err := federation.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	builder, err := federation.NewBuilder(store, a.Cert, a.Key, []*x509.Certificate{a.Root}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	compact, etag, err := builder.Current(now)
	if err != nil {
		t.Fatal(err)
	}
	opts := federation.VerifyOptions{OwnRoots: []*x509.Certificate{a.Root}, OwnScope: []string{domainA}, SignerConstraints: a.Cert.PermittedDNSDomains, Now: now}
	v, err := federation.Verify(compact, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Partners) != 1 || v.Partners[0].ID != "b-corp" || !v.Partners[0].Root.Equal(b.Root) || v.Bundle.Seq != 1 {
		t.Fatalf("内容が違う: %+v", v)
	}
	if !v.Bundle.Expires.Equal(v.Bundle.IssuedAt.Add(federation.DefaultBundleValidity)) {
		t.Errorf("有効期限が既定（2 日）でない: %v", v.Bundle.Expires.Sub(v.Bundle.IssuedAt))
	}
	// 変化がなければ同じもの、ファイルが変われば連番が進む。
	if c2, e2, _ := builder.Current(now); c2 != compact || e2 != etag {
		t.Error("変化が無いのに作り直した")
	}
	if err := federation.Update(path, func(f *federation.File) error { return f.Suspend("b-corp", federation.ByCLI("carol"), "", now) }); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	c3, _, _ := builder.Current(now)
	v3, err := federation.Verify(c3, opts)
	if err != nil || v3.Bundle.Seq != 2 || len(v3.Partners) != 0 || !v3.Bundle.IssuedAt.After(v.Bundle.IssuedAt) {
		t.Fatalf("停止が反映されない: %+v %v", v3, err)
	}

	// 期限切れ。
	if _, err := federation.Verify(compact, withNow(opts, now.Add(federation.DefaultBundleValidity+time.Minute))); !errors.Is(err, federation.ErrBundleExpired) {
		t.Errorf("期限切れ: %v", err)
	}
	// 自分のルートが CAFile に無い（別の CA のバンドル）。
	other := testca.NewIssuer(t, domainA)
	o2 := opts
	o2.OwnRoots = []*x509.Certificate{other.Root}
	if _, err := federation.Verify(compact, o2); err == nil {
		t.Error("別のルートの CA が署名したバンドルを受け付けた")
	}
	// ルートの入れ替え中（CAFile に新旧の 2 つ）は受け付ける。
	o3 := opts
	o3.OwnRoots = []*x509.Certificate{other.Root, a.Root}
	if _, err := federation.Verify(compact, o3); err != nil {
		t.Errorf("入れ替え中に拒否した: %v", err)
	}
	// 同じルートでも、名前制約の違う中間 CA が署名したものは受け付けない。
	o4 := opts
	o4.SignerConstraints = []string{"other.example.com"}
	if _, err := federation.Verify(compact, o4); err == nil {
		t.Error("名前制約の違う中間 CA の署名を受け付けた")
	}
	// 改ざん。
	parts := strings.Split(compact, ".")
	if _, err := federation.Verify(parts[0]+"."+parts[1]+"x."+parts[2], opts); err == nil {
		t.Error("改ざんしたバンドルを受け付けた")
	}
}

// 乗っ取られた CA が署名したバンドルでも、自分の範囲と重なる連携先・広すぎる範囲は受け付けない（設計 6-4）。
func TestVerifyDropsDangerousPartners(t *testing.T) {
	a := testca.NewIssuer(t, domainA)
	b := testca.NewIssuer(t, domainB)
	c := testca.NewIssuer(t, "c.example.org")
	now := time.Now()
	bp := func(id string, root *x509.Certificate, domains ...string) federation.BundlePartner {
		return federation.BundlePartner{ID: id, RootCert: string(pki.EncodeCertsPEM(root)), RootSHA256: federation.Fingerprint(root), Domains: domains, Expires: now.Add(time.Hour)}
	}
	bundle := &federation.Bundle{
		Format: federation.BundleFormat, Epoch: "e", Seq: 1, IssuedAt: now, Expires: now.Add(time.Hour),
		OwnRoots: []string{federation.Fingerprint(a.Root)},
		Partners: []federation.BundlePartner{
			bp("evil", c.Root, "x."+domainA),    // 自分の範囲と重なる
			bp("broad", c.Root, "com"),          // 広すぎる
			bp("self", a.Root, "z.example.net"), // 自分のルート
			bp("b-corp", b.Root, domainB),       // 正しい
			bp("dup", c.Root, "api."+domainB),   // 他の連携先と重なる
			bp("../x", c.Root, "c.example.org"), // 識別子が不正
		},
	}
	compact, err := federation.Sign(bundle, a.Cert, a.Key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := federation.Verify(compact, federation.VerifyOptions{OwnRoots: []*x509.Certificate{a.Root}, OwnScope: []string{domainA}, SignerConstraints: a.Cert.PermittedDNSDomains, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Partners) != 1 || v.Partners[0].ID != "b-corp" || len(v.Dropped) != 5 {
		t.Fatalf("partners=%v dropped=%v", v.Partners, v.Dropped)
	}
	// 自分のルートの指紋が無いバンドルは全体を拒否する。
	bundle.OwnRoots = nil
	compact, _ = federation.Sign(bundle, a.Cert, a.Key)
	if _, err := federation.Verify(compact, federation.VerifyOptions{OwnRoots: []*x509.Certificate{a.Root}, OwnScope: []string{domainA}, SignerConstraints: a.Cert.PermittedDNSDomains, Now: now}); err == nil {
		t.Error("自分のルートの指紋が無いバンドルを受け付けた")
	}
}

func TestDummyRootPEM(t *testing.T) {
	data, err := federation.DummyRootPEM()
	if err != nil {
		t.Fatal(err)
	}
	certs, err := pki.ParseCertsPEM(data)
	if err != nil || len(certs) != 1 || !certs[0].IsCA {
		t.Fatalf("PEM が不正: %v", err)
	}
	// どの証明書もこれにはつながらない。
	pool := x509.NewCertPool()
	pool.AddCert(certs[0])
	b := testca.NewIssuer(t, domainB)
	key, _ := pki.GenerateKey(pki.KeyECDSAP256)
	leaf, _ := b.IssueLeaf(key.Public(), []string{"web1." + domainB}, time.Hour)
	inter := x509.NewCertPool()
	inter.AddCert(b.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter}); err == nil {
		t.Error("ダミーの PEM で検証が通った")
	}
}

func withNow(o federation.VerifyOptions, now time.Time) federation.VerifyOptions {
	o.Now = now
	return o
}

// approve は path に連携先を取り込み、2 人で承認する。
func approve(t *testing.T, path, id string, root *x509.Certificate, domains, own []string) {
	t.Helper()
	rec, err := federation.NewRecord(root, domains, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	fp := federation.Fingerprint(root)
	if err := federation.Update(path, func(f *federation.File) error {
		if err := f.Import(id, rec, root, now, federation.ByCLI("alice")); err != nil {
			return err
		}
		if err := f.Request(id, federation.RequestOptions{Fingerprint: fp, ComparedWith: "電話", By: federation.ByCLI("alice")}, own, now); err != nil {
			return err
		}
		return f.Approve(id, fp, federation.ByCLI("bob"), own, now)
	}); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
