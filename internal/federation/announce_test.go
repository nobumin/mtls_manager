package federation_test

import (
	"crypto"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobumin/mtls_manager/internal/federation"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/testca"
)

// activePartner は連携先 b-corp を（CLI の 2 人で）承認した File を返す。
func activePartner(t *testing.T, root *x509.Certificate) *federation.File {
	t.Helper()
	rec, err := federation.NewRecord(root, []string{domainB}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	fp := federation.Fingerprint(root)
	now := time.Now()
	f := &federation.File{}
	if err := f.Import("b-corp", rec, root, now, federation.ByCLI("alice")); err != nil {
		t.Fatal(err)
	}
	if err := f.Request("b-corp", federation.RequestOptions{Fingerprint: fp, ComparedWith: "電話", By: federation.ByCLI("alice")}, []string{domainA}, now); err != nil {
		t.Fatal(err)
	}
	if err := f.Approve("b-corp", fp, federation.ByCLI("bob"), []string{domainA}, now); err != nil {
		t.Fatal(err)
	}
	return f
}

// 予告の取り込み → 次のルートの承認 → バンドルに新旧の両方 → 古いルートを外す。
func TestRootRotation(t *testing.T) {
	oldB, oldKey := testca.NewIssuerWithRootKey(t, domainB)
	newB := testca.NewIssuer(t, domainB)
	f := activePartner(t, oldB.Root)
	now := time.Now()

	a, err := federation.NewAnnouncement(oldB.Root, newB.Root, []string{domainB}, now.Add(7*24*time.Hour), 90*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := federation.SignAnnouncement(a, oldB.Root, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.ApproveNext("b-corp", federation.ByCLI("carol"), now); err == nil {
		t.Error("予告の前に次のルートを承認できた")
	}
	if err := f.ImportAnnouncement("b-corp", compact, federation.ByCLI("carol"), now); err != nil {
		t.Fatal(err)
	}
	p := f.Find("b-corp")
	if p.NextState != federation.NextPending || !federation.FingerprintEqual(p.NextRootSHA256, federation.Fingerprint(newB.Root)) {
		t.Fatalf("次のルートが承認待ちにならない: %+v", p)
	}
	// 承認待ちの次のルートは、まだバンドルに入らない。
	a1 := testca.NewIssuer(t, domainA)
	if v := buildAndVerify(t, f, a1); len(v.Partners[0].Roots) != 1 {
		t.Errorf("承認待ちの次のルートがバンドルに入った: %d", len(v.Partners[0].Roots))
	}
	if err := f.ApproveNext("b-corp", federation.ByCLI("carol"), now); err != nil {
		t.Fatal(err)
	}
	v := buildAndVerify(t, f, a1)
	if roots := v.Partners[0].Roots; len(roots) != 2 || !roots[0].Equal(oldB.Root) || !roots[1].Equal(newB.Root) {
		t.Fatalf("新旧の両方のルートがバンドルに入っていない: %d", len(roots))
	}
	if err := f.RetireRoot("b-corp", federation.ByCLI("carol"), now); err != nil {
		t.Fatal(err)
	}
	p = f.Find("b-corp")
	if !federation.FingerprintEqual(p.RootSHA256, federation.Fingerprint(newB.Root)) || p.NextState != "" {
		t.Fatalf("古いルートを外せていない: %+v", p)
	}
	if v := buildAndVerify(t, f, a1); len(v.Partners[0].Roots) != 1 || !v.Partners[0].Root.Equal(newB.Root) {
		t.Error("古いルートを外した後のバンドルが違う")
	}
}

// 予告の拒否: 別の鍵の署名・範囲の拡大・期限切れ・有効でない連携先。
func TestAnnouncementRejected(t *testing.T) {
	oldB, oldKey := testca.NewIssuerWithRootKey(t, domainB)
	newB := testca.NewIssuer(t, domainB)
	other, otherKey := testca.NewIssuerWithRootKey(t, domainB)
	now := time.Now()
	sign := func(old *x509.Certificate, key crypto.Signer, domains []string, at time.Time) string {
		t.Helper()
		a, err := federation.NewAnnouncement(old, newB.Root, domains, at, 90*24*time.Hour, at)
		if err != nil {
			t.Fatal(err)
		}
		c, err := federation.SignAnnouncement(a, old, key)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cases := map[string]string{
		"別のルートの鍵で署名":    sign(other.Root, otherKey, []string{domainB}, now),
		"範囲を広げる":        sign(oldB.Root, oldKey, []string{"example.net"}, now),
		"期限切れ（古い予告の再送）": sign(oldB.Root, oldKey, []string{domainB}, now.Add(-100*24*time.Hour)),
	}
	for name, c := range cases {
		f := activePartner(t, oldB.Root)
		if err := f.ImportAnnouncement("b-corp", c, federation.ByCLI("carol"), now); err == nil {
			t.Errorf("%s: 取り込めた", name)
		}
	}
	// 停止中の連携先には使えない（初回と同じ連携をやり直す）。
	f := activePartner(t, oldB.Root)
	_ = f.Suspend("b-corp", federation.ByCLI("carol"), "", now)
	if err := f.ImportAnnouncement("b-corp", sign(oldB.Root, oldKey, []string{domainB}, now), federation.ByCLI("carol"), now); err == nil {
		t.Error("停止中の連携先に予告を取り込めた")
	}
	// 申請し直すと、次のルートは消える（照合し直す）。
	f = activePartner(t, oldB.Root)
	if err := f.ImportAnnouncement("b-corp", sign(oldB.Root, oldKey, []string{domainB}, now), federation.ByCLI("carol"), now); err != nil {
		t.Fatal(err)
	}
	_ = f.Suspend("b-corp", federation.ByCLI("carol"), "", now)
	fp := federation.Fingerprint(oldB.Root)
	if err := f.Request("b-corp", federation.RequestOptions{Fingerprint: fp, ComparedWith: "電話", By: federation.ByCLI("alice")}, []string{domainA}, now); err != nil {
		t.Fatal(err)
	}
	if f.Find("b-corp").NextState != "" {
		t.Error("申請し直しても次のルートが残った")
	}
	// 予告そのものの改ざん。
	c := sign(oldB.Root, oldKey, []string{domainB}, now)
	parts := strings.Split(c, ".")
	if _, _, err := federation.VerifyAnnouncement(parts[0]+"."+parts[1]+"x."+parts[2], oldB.Root, now); err == nil {
		t.Error("改ざんした予告を受け入れた")
	}
}

// buildAndVerify は f の内容でバンドルを作り（a の中間 CA で署名）、検証した結果を返す。
func buildAndVerify(t *testing.T, f *federation.File, a *pki.Issuer) *federation.Verified {
	t.Helper()
	path := filepath.Join(t.TempDir(), "federation.json")
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	st, err := federation.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := federation.NewBuilder(st, a.Cert, a.Key, []*x509.Certificate{a.Root}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	compact, _, err := b.Current(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	v, err := federation.Verify(compact, federation.VerifyOptions{OwnRoots: []*x509.Certificate{a.Root}, OwnScope: []string{domainA}, SignerConstraints: a.Cert.PermittedDNSDomains, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Partners) != 1 {
		t.Fatalf("連携先が %d 件（%v）", len(v.Partners), v.Dropped)
	}
	return v
}
