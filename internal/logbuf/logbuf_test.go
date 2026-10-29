package logbuf

import (
	"io"
	"log/slog"
	"testing"
)

func TestBufferKeepsRecentAndFilters(t *testing.T) {
	b := New(3)
	log := slog.New(b.Handler(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.Info("一つ目")
	log.Warn("二つ目", "serial", "ab")
	log.With("component", "acme").Info("三つ目")
	log.Error("四つ目", slog.Group("req", "path", "/x"))

	all := b.Find(Query{})
	if len(all) != 3 || all[0].Msg != "二つ目" || all[2].Msg != "四つ目" {
		t.Fatalf("古いものから捨てていない: %+v", all)
	}
	if got := b.Find(Query{MinLevel: slog.LevelWarn}); len(got) != 2 {
		t.Errorf("重要度での絞り込み: %d 件", len(got))
	}
	if got := b.Find(Query{Text: "SERIAL=AB"}); len(got) != 1 || got[0].Msg != "二つ目" {
		t.Errorf("文字列での絞り込み: %+v", got)
	}
	if got := b.Find(Query{Text: "component=acme"}); len(got) != 1 {
		t.Errorf("With の属性が残っていない: %+v", got)
	}
	if got := b.Find(Query{Text: "req.path=/x"}); len(got) != 1 {
		t.Errorf("グループの属性が残っていない: %+v", got)
	}
	if got := b.Find(Query{After: all[1].Seq}); len(got) != 1 || got[0].Msg != "四つ目" {
		t.Errorf("連番での絞り込み: %+v", got)
	}
	if got := b.Find(Query{Limit: 1}); len(got) != 1 || got[0].Msg != "四つ目" {
		t.Errorf("件数の上限は新しいものを優先: %+v", got)
	}
}
