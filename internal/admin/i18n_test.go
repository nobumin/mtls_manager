package admin_test

import (
	"net/http"
	"strings"
	"testing"
	"unicode"

	"github.com/nobumin/mtls_manager/internal/i18n"
)

// MTLS_LANG=en のとき、管理画面は英語で表示する（lang 属性も en にする）。
func TestAdminPagesInEnglish(t *testing.T) {
	t.Cleanup(i18n.Set(i18n.English))
	e := start(t, nil)
	c := e.client(t, e.issuer, adminName)
	base := "https://" + e.addr
	for path, want := range map[string]string{
		"/":           "Valid certificates",
		"/certs":      "Issued certificates",
		"/federation": "Federation",
		"/logs":       "Auto refresh",
	} {
		res, body := get(t, c, base+path)
		if res.StatusCode != http.StatusOK || !strings.Contains(body, want) || !strings.Contains(body, `<html lang="en">`) {
			t.Errorf("%s: status=%d、英語の画面でない（%q を含まない）", path, res.StatusCode, want)
		}
		// 画面の文言に日本語が残っていないこと（データにはテスト用の日本語のメモがあるので、データの無い画面だけ確かめる）。
		if path == "/" || path == "/logs" {
			for _, r := range body {
				if unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana) {
					t.Errorf("%s: 英語の画面に日本語が残っている: %q", path, body)
					break
				}
			}
		}
	}
}
