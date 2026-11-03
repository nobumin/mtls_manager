// Package federation は、別々の mtls-ca（別々のルート CA）で管理するサーバ間の mTLS のための
// 連携（ルート CA の範囲付きの相互信頼）を扱う。設計は docs/ja/federation-design.md。
//
//   - Record: 組織どうしで交換する連携情報（公開情報のみ）
//   - File / Partner: CA 側で管理する連携先の一覧（承認の状態を含む）
//   - Bundle: CA が各サーバへ配るトラストバンドル（中間 CA の鍵で署名する）
//   - CheckPeer: 連携先のルートにつながる証明書の、形と範囲の検査
package federation

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nobumin/mtls_manager/internal/names"
	"github.com/nobumin/mtls_manager/internal/pki"
)

// RecordFormat は連携情報のファイルの形式。
const RecordFormat = "mtls-manager-federation/v1"

// Record は組織どうしで交換する連携情報。秘密情報は含まない。
// Organization と Contacts は相手の申告（未検証）で、指紋の照合の相手を決めるのには使わない。
type Record struct {
	Format       string    `json:"format"`
	Organization string    `json:"organization"`
	RootCert     string    `json:"root_cert"`
	RootSHA256   string    `json:"root_sha256"`
	Domains      []string  `json:"domains"`
	Contacts     []string  `json:"contacts,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// NewRecord は自分の連携情報を作る。
func NewRecord(root *x509.Certificate, domains []string, organization string, contacts []string) (*Record, error) {
	if err := CheckRoot(root); err != nil {
		return nil, err
	}
	ds, err := NormalizeScope(domains)
	if err != nil {
		return nil, err
	}
	return &Record{
		Format: RecordFormat, Organization: organization, RootCert: string(pki.EncodeCertsPEM(root)),
		RootSHA256: Fingerprint(root), Domains: ds, Contacts: contacts, CreatedAt: time.Now().UTC().Truncate(time.Second),
	}, nil
}

// ParseRecord は連携情報を読み、形式・ルート CA・指紋・範囲を確かめる。
func ParseRecord(data []byte) (*Record, *x509.Certificate, error) {
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, nil, fmt.Errorf("連携情報を解釈できない: %w", err)
	}
	if r.Format != RecordFormat {
		return nil, nil, fmt.Errorf("連携情報の形式 %q に対応していない（%s）", r.Format, RecordFormat)
	}
	root, err := parseRoot(r.RootCert)
	if err != nil {
		return nil, nil, err
	}
	if !FingerprintEqual(r.RootSHA256, Fingerprint(root)) {
		return nil, nil, errors.New("root_sha256 がルート CA の証明書と一致しない")
	}
	if r.Domains, err = NormalizeScope(r.Domains); err != nil {
		return nil, nil, err
	}
	return &r, root, nil
}

func parseRoot(pemText string) (*x509.Certificate, error) {
	certs, err := pki.ParseCertsPEM([]byte(pemText))
	if err != nil {
		return nil, fmt.Errorf("ルート CA の証明書を解釈できない: %w", err)
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("ルート CA の証明書は 1 枚にする（%d 枚ある）", len(certs))
	}
	if err := CheckRoot(certs[0]); err != nil {
		return nil, err
	}
	return certs[0], nil
}

// CheckRoot はルート CA として正しいか（自己署名・CA・期限内・鍵の種類と長さ）を確かめる。
func CheckRoot(c *x509.Certificate) error {
	if !c.IsCA || !c.BasicConstraintsValid {
		return errors.New("ルート CA ではない（CA:TRUE でない）")
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		return errors.New("ルート CA ではない（自己署名でない）")
	}
	now := time.Now()
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return errors.New("ルート CA の証明書が有効期間の外")
	}
	return pki.CheckPublicKey(c.PublicKey)
}

// Fingerprint は証明書の SHA-256（DER）を、2 桁ずつコロンで区切った大文字の 16 進で返す。
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// NormalizeFingerprint は区切り（コロン・空白・ハイフン）を除き、大文字の 64 桁にする。64 桁の 16 進でなければ空を返す。
func NormalizeFingerprint(s string) string {
	s = strings.ToUpper(strings.Map(func(r rune) rune {
		if r == ':' || r == ' ' || r == '-' || r == '\t' {
			return -1
		}
		return r
	}, s))
	if len(s) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}

// FingerprintEqual は 2 つの指紋が同じかを返す（書き方の違いは問わない）。どちらかが不正なら false。
func FingerprintEqual(a, b string) bool {
	na, nb := NormalizeFingerprint(a), NormalizeFingerprint(b)
	return na != "" && na == nb
}

// idRe は連携先の識別子（自分の側で付ける。ファイル名に使う）の書式。
var idRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)

// ValidateID は連携先の識別子の書式（[a-z0-9-]{1,32}、先頭・末尾はハイフン不可）を確かめる。
func ValidateID(id string) error {
	if !idRe.MatchString(id) {
		return fmt.Errorf("連携先の識別子 %q は英小文字・数字・ハイフンの 1〜32 文字にする（先頭・末尾はハイフン不可）", id)
	}
	return nil
}

func sortedUnique(list []string) []string {
	out := slices.Clone(list)
	slices.Sort(out)
	return slices.Compact(out)
}

// normalizeAll は名前を Normalize して返す。
func normalizeAll(list []string) []string {
	out := make([]string, 0, len(list))
	for _, d := range list {
		out = append(out, names.Normalize(d))
	}
	return out
}
