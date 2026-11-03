package admin_test

import (
	"os"
	"testing"

	"github.com/nobumin/mtls_manager/internal/i18n"
)

// TestMain は文言を日本語に固定する。このパッケージのテストは日本語の文言を照合するので、
// 開発者のシェルの MTLS_LANG に左右されないようにする（英語を確かめるテストは、個別に i18n.Set(i18n.English) を使う）。
func TestMain(m *testing.M) {
	i18n.Set(i18n.Japanese)
	os.Exit(m.Run())
}
