package acmeserver

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/nobumin/mtls_manager/internal/pki"
)

// 中間 CA の残りが短くても、作り直した直後に更新時期を過ぎていない（TLS の接続のたびに作り直さない）。
func TestSelfCertRenewAtNearIntermediateExpiry(t *testing.T) {
	rootKey, _ := pki.GenerateKey(pki.KeyECDSAP256)
	root, err := pki.CreateRoot(rootKey, pki.RootOptions{CommonName: "Test Root", Validity: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	interKey, _ := pki.GenerateKey(pki.KeyECDSAP256)
	csrDER, _ := pki.CreateCSR(interKey, "Test Intermediate", "")
	csr, _ := x509.ParseCertificateRequest(csrDER)
	// 中間 CA の残りは 2 分（NotBefore を 5 分過去にずらすので、旧来の計算なら発行時点で更新時期を過ぎる）。
	inter, err := pki.SignIntermediate(root, rootKey, csr, pki.IntermediateOptions{Validity: 2 * time.Minute, PermittedDomains: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	iss, err := pki.NewIssuer(inter, interKey, root)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSelfCert(iss, []string{"ca.example.com"}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !s.renewAt.After(time.Now().Add(50 * time.Second)) {
		t.Fatalf("作り直した直後なのに更新時期が近すぎる: renew_at=%v", s.renewAt)
	}
	if s.renewAt.After(s.cur.Leaf.NotAfter) {
		t.Fatalf("更新時期 %v が証明書の期限 %v より後", s.renewAt, s.cur.Leaf.NotAfter)
	}
}
