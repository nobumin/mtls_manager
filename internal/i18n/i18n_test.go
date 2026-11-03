package i18n_test

import (
	"testing"

	"github.com/nobumin/mtls_manager/internal/i18n"
)

func TestParse(t *testing.T) {
	for in, want := range map[string]i18n.Lang{
		"ja": i18n.Japanese, "ja_JP.UTF-8": i18n.Japanese, "JA": i18n.Japanese,
		"en": i18n.English, "en_US.UTF-8": i18n.English, "en-GB": i18n.English, " EN ": i18n.English, "en@euro": i18n.English,
	} {
		if got, ok := i18n.Parse(in); !ok || got != want {
			t.Errorf("Parse(%q) = %v, %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "fr", "C", "C.UTF-8", "english", "jp"} {
		if got, ok := i18n.Parse(in); ok || got != i18n.Japanese {
			t.Errorf("Parse(%q) = %v, %v（日本語・false のはず）", in, got, ok)
		}
	}
}

func TestSetAndT(t *testing.T) {
	restore := i18n.Set(i18n.Japanese)
	defer restore()
	if got := i18n.T("日本語", "English"); got != "日本語" {
		t.Errorf("日本語のとき %q", got)
	}
	back := i18n.Set(i18n.English)
	if got := i18n.T("日本語", "English"); got != "English" || i18n.Current().String() != "en" {
		t.Errorf("英語のとき %q（%s）", got, i18n.Current())
	}
	back()
	if i18n.Current() != i18n.Japanese {
		t.Error("Set の戻す関数で元に戻らない")
	}
}

func TestErrorFollowsCurrentLanguage(t *testing.T) {
	t.Cleanup(i18n.Set(i18n.Japanese))
	err := i18n.Error("失敗した", "failed")
	if err.Error() != "失敗した" {
		t.Errorf("日本語のとき %q", err)
	}
	i18n.Set(i18n.English)
	if err.Error() != "failed" {
		t.Errorf("英語のとき %q（作った後で言語を変えても追従する）", err)
	}
}
