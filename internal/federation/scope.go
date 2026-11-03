package federation

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/nobumin/mtls_manager/internal/names"
)

// NormalizeScope は範囲（ドメインの一覧）を正規化し、広すぎないことを確かめる。
//   - 各ドメインは書式が正しく、2 ラベル以上（`net` は不可）
//   - パブリックサフィックス（`com`・`co.jp` など）そのものは不可
//   - 空の範囲は不可
func NormalizeScope(domains []string) ([]string, error) {
	if len(domains) == 0 {
		return nil, errors.New("範囲（ドメイン）が空")
	}
	out := normalizeAll(domains)
	for _, d := range out {
		if err := names.ValidateDomain(d); err != nil {
			return nil, fmt.Errorf("範囲: %w", err)
		}
		if !strings.Contains(d, ".") {
			return nil, fmt.Errorf("範囲 %q は広すぎる（2 ラベル以上にする）", d)
		}
		if suffix, _ := publicsuffix.PublicSuffix(d); suffix == d {
			return nil, fmt.Errorf("範囲 %q はパブリックサフィックスなので使えない", d)
		}
	}
	return sortedUnique(out), nil
}

// ScopesOverlap は 2 つの範囲に、両方に入る名前があり得るかを返す（一方が他方と同じかサブドメイン）。
func ScopesOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if names.WithinDomain(x, y) || names.WithinDomain(y, x) {
				return true
			}
		}
	}
	return false
}

// WithinScope は narrow のすべてのドメインが、wide のいずれかの配下にあるかを返す（範囲を狭めることの確認）。
func WithinScope(narrow, wide []string) bool {
	for _, d := range narrow {
		if !names.WithinAnyDomain(wide, d) {
			return false
		}
	}
	return true
}

// OwnScope は自分の範囲を、自分の中間 CA の名前制約から得る。中間 CA はオフラインのルートが署名しているので、
// オンラインの CA サーバでは書き換えられない（設計 6-4）。
//   - inter は roots のいずれかで検証できること
//   - narrow（ローカルの設定）は範囲を狭めるためだけに使う。名前制約より広い値はエラー
//   - 名前制約が無い・空なら、範囲は得られない（エラー。連携先を 1 つも信頼しない）
func OwnScope(inter *x509.Certificate, roots *x509.CertPool, narrow []string) ([]string, error) {
	if inter == nil {
		return nil, errors.New("自分の中間 CA の証明書が無い")
	}
	if _, err := inter.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("自分の中間 CA の証明書を、自分のルート CA で検証できない: %w", err)
	}
	if !inter.IsCA {
		return nil, errors.New("自分の中間 CA の証明書が CA ではない")
	}
	permitted := normalizeAll(inter.PermittedDNSDomains)
	permitted = slices.DeleteFunc(permitted, func(d string) bool { return d == "" })
	if len(permitted) == 0 {
		return nil, errors.New("自分の中間 CA に名前制約が無いので、自分の範囲が決まらない（連携版は名前制約のある中間 CA が必要）")
	}
	if len(narrow) == 0 {
		return sortedUnique(permitted), nil
	}
	n := normalizeAll(narrow)
	if !WithinScope(n, permitted) {
		return nil, fmt.Errorf("own_domains %v が中間 CA の名前制約 %v より広い（狭めることだけができる）", n, permitted)
	}
	return sortedUnique(n), nil
}

// CheckPeer は連携先のルートにつながる証明書が、受け入れてよい形で、名前がすべて範囲に入るかを確かめる（設計 6-2）。
//   - DNS 名が 1 つ以上ある
//   - DNS 名にワイルドカードを含まない
//   - DNS 名以外の SAN（IP アドレス・URI・メールアドレス）を含まない
//   - DNS 名がすべて scope の配下にある
func CheckPeer(leaf *x509.Certificate, scope []string) error {
	if len(leaf.DNSNames) == 0 {
		return errors.New("連携先の証明書に DNS 名が無い")
	}
	if len(leaf.IPAddresses) > 0 || len(leaf.URIs) > 0 || len(leaf.EmailAddresses) > 0 {
		return errors.New("連携先の証明書に DNS 名以外の名前（IP アドレス・URI・メールアドレス）がある")
	}
	for _, n := range leaf.DNSNames {
		n = names.Normalize(n)
		if strings.Contains(n, "*") {
			return fmt.Errorf("連携先の証明書にワイルドカードの名前 %q がある", n)
		}
		if !names.WithinAnyDomain(scope, n) {
			return fmt.Errorf("連携先の証明書の名前 %q が、その連携先の範囲 %v の外", n, scope)
		}
	}
	return nil
}
