package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"time"

	"github.com/nobumin/mtls_manager/internal/names"
)

// clockSkew は発行時に NotBefore を過去へずらす幅。サーバ間の時計のずれで「まだ有効でない」とならないようにする。
const clockSkew = 5 * time.Minute

// EncodeCertsPEM は証明書を PEM で連結する。
func EncodeCertsPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// ParseCertsPEM は PEM から証明書をすべて読む。
func ParseCertsPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("証明書の PEM ブロックが見つからない")
	}
	return certs, nil
}

// LoadCerts は証明書ファイルを読む。
func LoadCerts(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certs, err := ParseCertsPEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return certs, nil
}

// LoadCert は証明書ファイルの先頭の 1 枚を読む。
func LoadCert(path string) (*x509.Certificate, error) {
	certs, err := LoadCerts(path)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// RandomSerial は 128 bit の正の乱数シリアルを返す。
func RandomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// RootOptions はルート CA の作成条件。
type RootOptions struct {
	CommonName   string
	Organization string
	Validity     time.Duration
}

// CreateRoot は自己署名のルート CA 証明書を作る。中間 CA を 1 段だけ持てる（MaxPathLen=1）。
func CreateRoot(key crypto.Signer, o RootOptions) (*x509.Certificate, error) {
	if o.CommonName == "" {
		return nil, errors.New("ルート CA の CN が空")
	}
	serial, err := RandomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject(o.CommonName, o.Organization),
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(o.Validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// CreateCSR は CN だけを持つ CSR（DER）を作る。中間 CA の鍵を CA サーバ上で作り、
// ルート CA の鍵があるオフライン端末で署名してもらうために使う。
func CreateCSR(key crypto.Signer, commonName, organization string) ([]byte, error) {
	if commonName == "" {
		return nil, errors.New("CN が空")
	}
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: subject(commonName, organization),
	}, key)
}

// EncodeCSRPEM は CSR を PEM にする。
func EncodeCSRPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// ParseCSRPEM は PEM の CSR を読み、署名を検証する。
func ParseCSRPEM(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("CSR の PEM ブロックが見つからない")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR の署名が不正: %w", err)
	}
	return csr, nil
}

// IntermediateOptions は中間 CA の署名条件。
type IntermediateOptions struct {
	Validity time.Duration
	// PermittedDomains は名前制約（Name Constraints）。中間 CA が発行できる名前をこのドメイン配下に限る。
	// 空なら制約なし（非推奨）。
	PermittedDomains []string
}

// SignIntermediate はルート CA で中間 CA の CSR に署名する。
// 中間 CA はさらに下位の CA を作れず（MaxPathLen=0）、用途はサーバ認証・クライアント認証に限る。
func SignIntermediate(root *x509.Certificate, rootKey crypto.Signer, csr *x509.CertificateRequest, o IntermediateOptions) (*x509.Certificate, error) {
	if err := CheckPublicKey(csr.PublicKey); err != nil {
		return nil, err
	}
	if !PublicKeyEqual(root.PublicKey, rootKey.Public()) {
		return nil, errors.New("ルート CA の証明書と秘密鍵が対応していない")
	}
	permitted := make([]string, 0, len(o.PermittedDomains))
	for _, d := range o.PermittedDomains {
		d = names.Normalize(d)
		if err := names.ValidateDomain(d); err != nil {
			return nil, fmt.Errorf("名前制約: %w", err)
		}
		permitted = append(permitted, d)
	}
	serial, err := RandomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(o.Validity)
	if notAfter.After(root.NotAfter) {
		notAfter = root.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     csr.Subject,
		NotBefore:                   now.Add(-clockSkew),
		NotAfter:                    notAfter,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		PermittedDNSDomains:         permitted,
		PermittedDNSDomainsCritical: len(permitted) > 0,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, csr.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Issuer は中間 CA の証明書と鍵で末端の証明書を発行する。
type Issuer struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	Root *x509.Certificate
}

// NewIssuer は中間 CA の証明書・鍵・ルートの組み合わせが正しいことを確かめる。
func NewIssuer(intermediate *x509.Certificate, key crypto.Signer, root *x509.Certificate) (*Issuer, error) {
	if !intermediate.IsCA {
		return nil, errors.New("中間 CA の証明書が CA ではない")
	}
	if !PublicKeyEqual(intermediate.PublicKey, key.Public()) {
		return nil, errors.New("中間 CA の証明書と秘密鍵が対応していない")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := intermediate.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("中間 CA がルート CA につながらない: %w", err)
	}
	return &Issuer{Cert: intermediate, Key: key, Root: root}, nil
}

// LoadIssuer はファイルから Issuer を作る。
func LoadIssuer(intermediatePath, keyPath, rootPath string) (*Issuer, error) {
	inter, err := LoadCert(intermediatePath)
	if err != nil {
		return nil, err
	}
	key, err := LoadPrivateKey(keyPath)
	if err != nil {
		return nil, err
	}
	root, err := LoadCert(rootPath)
	if err != nil {
		return nil, err
	}
	return NewIssuer(inter, key, root)
}

// Permits は名前が中間 CA の名前制約の範囲内かを返す（制約なしなら常に true）。
func (i *Issuer) Permits(name string) bool {
	return len(i.Cert.PermittedDNSDomains) == 0 || names.WithinAnyDomain(i.Cert.PermittedDNSDomains, name)
}

// ErrIssuerExpiring は中間 CA の残りの有効期間が短すぎて、発行を拒否したことを表す。
var ErrIssuerExpiring = errors.New("中間 CA の有効期限が近く、証明書の有効期間を確保できない（中間 CA を更新すること）")

// LeafNotAfter は validity で発行したときの NotAfter（中間 CA の期限で切り詰めたもの）を返す。
func (i *Issuer) LeafNotAfter(now time.Time, validity time.Duration) time.Time {
	if notAfter := now.Add(validity); notAfter.Before(i.Cert.NotAfter) {
		return notAfter
	}
	return i.Cert.NotAfter
}

// IssueLeaf はサーバ認証・クライアント認証の両方に使える末端の証明書を、ランダムなシリアルで発行する。
// dnsNames は検証済み・正規化済みであること。
func (i *Issuer) IssueLeaf(pub crypto.PublicKey, dnsNames []string, validity time.Duration) (*x509.Certificate, error) {
	serial, err := RandomSerial()
	if err != nil {
		return nil, err
	}
	return i.IssueLeafWithSerial(serial, pub, dnsNames, validity)
}

// IssueLeafWithSerial は指定のシリアルで発行する（発行前にシリアルを記録しておくため）。
// 中間 CA の期限で切り詰めた結果、有効期間が validity の半分を下回る場合は ErrIssuerExpiring を返す
// （短い証明書を全サーバが取り直し続けるのを防ぐ）。
func (i *Issuer) IssueLeafWithSerial(serial *big.Int, pub crypto.PublicKey, dnsNames []string, validity time.Duration) (*x509.Certificate, error) {
	if len(dnsNames) == 0 {
		return nil, errors.New("名前が空")
	}
	if err := CheckPublicKey(pub); err != nil {
		return nil, err
	}
	for _, n := range dnsNames {
		if !i.Permits(n) {
			return nil, fmt.Errorf("%q は中間 CA の名前制約 %v の範囲外", n, i.Cert.PermittedDNSDomains)
		}
	}
	now := time.Now()
	notAfter := i.LeafNotAfter(now, validity)
	if notAfter.Sub(now) < validity/2 {
		return nil, ErrIssuerExpiring
	}
	ku := x509.KeyUsageDigitalSignature
	if _, ok := pub.(*rsa.PublicKey); ok {
		ku |= x509.KeyUsageKeyEncipherment
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		DNSNames:              slices.Clone(dnsNames),
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              ku,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.Cert, pub, i.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// RevokedEntry は CRL に載せる失効情報。
type RevokedEntry struct {
	Serial    *big.Int
	RevokedAt time.Time
	Reason    int
}

// CreateCRL は中間 CA で署名した CRL（DER）を作る。
func (i *Issuer) CreateCRL(entries []RevokedEntry, number *big.Int, validity time.Duration) ([]byte, error) {
	now := time.Now()
	list := make([]x509.RevocationListEntry, 0, len(entries))
	for _, e := range entries {
		list = append(list, x509.RevocationListEntry{SerialNumber: e.Serial, RevocationTime: e.RevokedAt, ReasonCode: e.Reason})
	}
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificateEntries: list,
		Number:                    number,
		ThisUpdate:                now.Add(-clockSkew),
		NextUpdate:                now.Add(validity),
	}, i.Cert, i.Key)
}

func subject(cn, org string) pkix.Name {
	n := pkix.Name{CommonName: cn}
	if org != "" {
		n.Organization = []string{org}
	}
	return n
}
