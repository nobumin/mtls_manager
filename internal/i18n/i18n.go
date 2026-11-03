// Package i18n は、利用者に見せる文言（ログ・エラー・CLI の表示・ACME の応答・管理画面）の言語を切り替える。
//
// 既定は日本語で、環境変数 MTLS_LANG が en（en_US.UTF-8 なども可）のときは英語にする。
// 文言は呼び出し側に日本語と英語を並べて書く（i18n.T("日本語", "English")）。日本語を正とし、
// 両方の書式指定（%s など）の並びをそろえる（coverage_test.go が確かめる）。
package i18n

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

// Lang は文言の言語。
type Lang int32

const (
	Japanese Lang = iota
	English
)

// EnvVar は言語を指定する環境変数の名前。
const EnvVar = "MTLS_LANG"

var (
	current    atomic.Int32
	invalidEnv string
)

func init() {
	v := os.Getenv(EnvVar)
	l, ok := Parse(v)
	if !ok && v != "" {
		invalidEnv = v
	}
	current.Store(int32(l))
}

// Parse は "ja" / "en" を解釈する。"en_US.UTF-8"・"en-US"・"EN" のような書き方も受け付ける。
// 解釈できなければ Japanese と false を返す。
func Parse(s string) (Lang, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexAny(s, "_-.@"); i >= 0 {
		s = s[:i]
	}
	switch s {
	case "ja":
		return Japanese, true
	case "en":
		return English, true
	}
	return Japanese, false
}

// InvalidEnv は、環境変数 MTLS_LANG に解釈できない値が入っていたとき、その値と true を返す（起動時の警告用）。
func InvalidEnv() (string, bool) { return invalidEnv, invalidEnv != "" }

// Current は現在の言語を返す。
func Current() Lang { return Lang(current.Load()) }

// Set は言語を変え、元に戻す関数を返す（主にテスト用。t.Cleanup(i18n.Set(i18n.English)) のように使う）。
func Set(l Lang) (restore func()) {
	prev := Lang(current.Swap(int32(l)))
	return func() { current.Store(int32(prev)) }
}

// T は現在の言語の文言を返す。日本語を先に書く。
func T(ja, en string) string {
	if Current() == English {
		return en
	}
	return ja
}

// String は "ja" / "en" を返す（HTML の lang 属性などに使う）。
func (l Lang) String() string {
	if l == English {
		return "en"
	}
	return "ja"
}

// InvalidEnvWarning は、MTLS_LANG に解釈できない値が入っていたときの警告文を返す（無ければ空）。
// 指定した人は英語を読みたい可能性が高いので、日本語と英語を並べる。
func InvalidEnvWarning() string {
	v, ok := InvalidEnv()
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s の値 %q を解釈できないので、日本語で表示する（ja か en を指定する） / cannot parse %s=%q; showing messages in Japanese (use ja or en)", EnvVar, v, EnvVar, v)
}

// Error は、表示するときの言語で文言を返すエラーを作る（errors.Is で比べる番兵のエラー用）。
// パッケージの変数で errors.New(i18n.T(...)) とすると、初期化のときの言語で固定されてしまうため。
func Error(ja, en string) error { return &msgError{ja, en} }

type msgError struct{ ja, en string }

func (e *msgError) Error() string { return T(e.ja, e.en) }
