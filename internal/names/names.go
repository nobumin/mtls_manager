// Package names は DNS 名の正規化・検証と、許可パターンとの照合を行う。
//
// パターンの書式（EAB 鍵の names、ライブラリの許可リストで共通）:
//
//	"web1.internal.example.com" … 完全一致
//	"*.internal.example.com"    … internal.example.com の直下 1 ラベルだけに一致
//	                              （a.internal.example.com は一致、a.b.internal.example.com と
//	                               internal.example.com 自身は不一致）
//
// ドメイン（CA の allowed_domains、中間 CA の名前制約）は「そのドメイン自身とすべてのサブドメイン」を表す。
package names

import (
	"errors"
	"fmt"
	"strings"
)

// Normalize は小文字化し、末尾のドットを取り除く。
func Normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// ValidateHostname は name が証明書に載せてよいホスト名（ワイルドカード不可）かを確かめる。
// name は Normalize 済みであること。
func ValidateHostname(name string) error {
	if name == "" {
		return errors.New("空の名前")
	}
	if len(name) > 253 {
		return fmt.Errorf("%q: 253 文字を超えている", name)
	}
	if !strings.Contains(name, ".") {
		return fmt.Errorf("%q: FQDN（ドットを含む名前）を指定する", name)
	}
	return ValidateDomain(name)
}

// ValidateDomain はドメイン名（1 ラベルでもよい。例: "corp"）の書式を確かめる。
// 名前制約・発行してよいドメインの指定に使う。name は Normalize 済みであること。
func ValidateDomain(name string) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("%q: 長さが不正", name)
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if err := validateLabel(l); err != nil {
			return fmt.Errorf("%q: %w", name, err)
		}
	}
	// 最上位のラベルが数字だけの名前は IP アドレスと紛らわしいので受け付けない（RFC 1123 §2.1）。
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return fmt.Errorf("%q: 最上位のラベルが数字だけの名前は使えない", name)
	}
	return nil
}

func validateLabel(l string) error {
	if l == "" {
		return errors.New("空のラベルがある")
	}
	if len(l) > 63 {
		return errors.New("63 文字を超えるラベルがある")
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return errors.New("ラベルの先頭・末尾にハイフンは使えない")
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("使えない文字 %q がある（英小文字・数字・ハイフンのみ）", c)
		}
	}
	return nil
}

// ValidatePattern はパターンの書式を確かめる。
func ValidatePattern(p string) error {
	if rest, ok := strings.CutPrefix(p, "*."); ok {
		return ValidateHostname(rest)
	}
	if strings.Contains(p, "*") {
		return fmt.Errorf("%q: ワイルドカードは先頭の \"*.\" のみ使える", p)
	}
	return ValidateHostname(p)
}

// MatchPattern は name がパターン p に一致するかを返す。どちらも Normalize 済みであること。
func MatchPattern(p, name string) bool {
	if rest, ok := strings.CutPrefix(p, "*."); ok {
		label, parent, found := strings.Cut(name, ".")
		return found && label != "" && parent == rest
	}
	return p == name
}

// MatchAny は name がいずれかのパターンに一致するかを返す。
func MatchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if MatchPattern(p, name) {
			return true
		}
	}
	return false
}

// WithinDomain は name が domain 自身またはそのサブドメインかを返す。
func WithinDomain(domain, name string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// WithinAnyDomain は name がいずれかのドメイン配下かを返す。
func WithinAnyDomain(domains []string, name string) bool {
	for _, d := range domains {
		if WithinDomain(d, name) {
			return true
		}
	}
	return false
}

// Overlap は 2 つのパターンの両方に一致する名前があり得るかを返す。どちらも Normalize 済みであること。
func Overlap(a, b string) bool {
	aw, bw := strings.HasPrefix(a, "*."), strings.HasPrefix(b, "*.")
	switch {
	case aw && bw, !aw && !bw:
		return a == b
	case aw:
		return MatchPattern(a, b)
	default:
		return MatchPattern(b, a)
	}
}
