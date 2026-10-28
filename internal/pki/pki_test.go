package pki

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestIssuer はテスト用のルート CA と中間 CA をその場で作る（鍵ファイルはリポジトリに置かない）。
func newTestIssuer(t *testing.T, permitted ...string) *Issuer {
	t.Helper()
	rootKey, err := GenerateKey(KeyECDSAP384)
	if err != nil {
		t.Fatal(err)
	}
	root, err := CreateRoot(rootKey, RootOptions{CommonName: "Test Root", Validity: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	interKey, err := GenerateKey(KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := CreateCSR(interKey, "Test Intermediate", "")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCSRPEM(EncodeCSRPEM(csrDER))
	if err != nil {
		t.Fatal(err)
	}
	inter, err := SignIntermediate(root, rootKey, csr, IntermediateOptions{Validity: 12 * time.Hour, PermittedDomains: permitted})
	if err != nil {
		t.Fatal(err)
	}
	iss, err := NewIssuer(inter, interKey, root)
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func TestIssueLeafVerifiesForBothUsages(t *testing.T) {
	iss := newTestIssuer(t, "internal.example.com")
	leafKey, _ := GenerateKey(KeyECDSAP256)
	leaf, err := iss.IssueLeaf(leafKey.Public(), []string{"web1.internal.example.com"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(iss.Root)
	inters := x509.NewCertPool()
	inters.AddCert(iss.Cert)
	for _, ku := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: inters, DNSName: "web1.internal.example.com",
			KeyUsages: []x509.ExtKeyUsage{ku},
		}); err != nil {
			t.Errorf("用途 %v で検証に失敗: %v", ku, err)
		}
	}
	if leaf.NotAfter.After(time.Now().Add(time.Hour)) {
		t.Errorf("有効期限が長すぎる: %v", leaf.NotAfter)
	}
}

func TestIssueLeafRejectsOutsideNameConstraints(t *testing.T) {
	iss := newTestIssuer(t, "internal.example.com")
	leafKey, _ := GenerateKey(KeyECDSAP256)
	if _, err := iss.IssueLeaf(leafKey.Public(), []string{"web1.other.example.com"}, time.Hour); err == nil {
		t.Fatal("名前制約の範囲外なのに発行できた")
	}
}

// 名前制約はアプリ側の事前確認だけでなく、検証側（x509.Verify）でも効くことを確かめる。
func TestNameConstraintsEnforcedByVerifier(t *testing.T) {
	iss := newTestIssuer(t, "internal.example.com")
	// 事前確認を外した Issuer で範囲外の証明書を作り、検証で弾かれることを見る。
	unchecked := &Issuer{Cert: &x509.Certificate{}, Key: iss.Key, Root: iss.Root}
	*unchecked.Cert = *iss.Cert
	unchecked.Cert.PermittedDNSDomains = nil
	leafKey, _ := GenerateKey(KeyECDSAP256)
	leaf, err := unchecked.IssueLeaf(leafKey.Public(), []string{"evil.example.org"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(iss.Root)
	inters := x509.NewCertPool()
	inters.AddCert(iss.Cert)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err == nil {
		t.Fatal("名前制約の範囲外の証明書が検証を通った")
	}
}

func TestNewIssuerRejectsMismatchedKey(t *testing.T) {
	iss := newTestIssuer(t)
	other, _ := GenerateKey(KeyECDSAP256)
	if _, err := NewIssuer(iss.Cert, other, iss.Root); err == nil {
		t.Fatal("鍵が対応していないのに通った")
	}
}

func TestPrivateFilePermissions(t *testing.T) {
	dir := t.TempDir()
	key, _ := GenerateKey(KeyECDSAP256)
	path := filepath.Join(dir, "k.pem")
	if err := SavePrivateKey(path, key); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(path); err != nil {
		t.Fatalf("0600 の鍵が読めない: %v", err)
	}
	if err := SavePrivateKey(path, key); err == nil {
		t.Fatal("既存の鍵を上書きできてしまった")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(path); err == nil || !strings.Contains(err.Error(), "権限") {
		t.Fatalf("0644 の鍵を拒否しなかった: %v", err)
	}
}

func TestCreateCRL(t *testing.T) {
	iss := newTestIssuer(t)
	serial, _ := RandomSerial()
	der, err := iss.CreateCRL([]RevokedEntry{{Serial: serial, RevokedAt: time.Now(), Reason: 1}}, serial, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(iss.Cert); err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(serial) != 0 {
		t.Fatalf("CRL の内容が不正: %+v", crl.RevokedCertificateEntries)
	}
}
