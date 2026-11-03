// Package logbuf は直近のログをメモリ上に保持する（管理画面でのログの閲覧用）。
//
// 保持するのはプロセスの起動以降の、件数の上限までの分だけ。長期の保存は journald などの
// 通常のログの出力先に任せる。
package logbuf

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Attr はログの属性（キーと値）。
type Attr struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Entry は 1 件のログ。
type Entry struct {
	Seq   uint64     `json:"seq"`
	Time  time.Time  `json:"time"`
	Level slog.Level `json:"level"`
	Msg   string     `json:"msg"`
	Attrs []Attr     `json:"attrs"`
}

// Buffer は件数に上限のあるログの保持先。古いものから捨てる。
type Buffer struct {
	mu      sync.Mutex
	entries []Entry
	next    int
	full    bool
	seq     uint64
}

// New は最大 size 件を保持する Buffer を作る。
func New(size int) *Buffer {
	return &Buffer{entries: make([]Entry, size)}
}

func (b *Buffer) add(e Entry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	e.Seq = b.seq
	b.entries[b.next] = e
	b.next = (b.next + 1) % len(b.entries)
	if b.next == 0 {
		b.full = true
	}
}

// Query は絞り込みの条件。
type Query struct {
	After    uint64     // この連番より後のものだけ
	MinLevel slog.Level // この重要度以上のものだけ
	Text     string     // メッセージか属性にこの文字列を含むものだけ（大文字小文字を区別しない）
	Limit    int        // 最大件数（新しいものを優先）。0 なら上限なし
}

// Find は条件に合うログを古い順に返す。
func (b *Buffer) Find(q Query) []Entry {
	b.mu.Lock()
	all := make([]Entry, 0, len(b.entries))
	if b.full {
		all = append(all, b.entries[b.next:]...)
	}
	all = append(all, b.entries[:b.next]...)
	b.mu.Unlock()

	text := strings.ToLower(q.Text)
	out := make([]Entry, 0)
	for _, e := range all {
		if e.Seq <= q.After || e.Level < q.MinLevel {
			continue
		}
		if text != "" && !e.contains(text) {
			continue
		}
		out = append(out, e)
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[len(out)-q.Limit:]
	}
	return out
}

func (e Entry) contains(lower string) bool {
	if strings.Contains(strings.ToLower(e.Msg), lower) {
		return true
	}
	for _, a := range e.Attrs {
		if strings.Contains(strings.ToLower(a.Key+"="+a.Value), lower) {
			return true
		}
	}
	return false
}

// Handler は next にログを渡しつつ、同じ内容を Buffer にも残す slog.Handler を返す。
func (b *Buffer) Handler(next slog.Handler) slog.Handler {
	return &tee{next: next, buf: b}
}

type tee struct {
	next   slog.Handler
	buf    *Buffer
	attrs  []Attr
	prefix string // WithGroup で付くキーの接頭辞
}

func (t *tee) Enabled(ctx context.Context, l slog.Level) bool { return t.next.Enabled(ctx, l) }

func (t *tee) Handle(ctx context.Context, r slog.Record) error {
	e := Entry{Time: r.Time, Level: r.Level, Msg: r.Message, Attrs: append([]Attr(nil), t.attrs...)}
	r.Attrs(func(a slog.Attr) bool {
		e.Attrs = appendAttr(e.Attrs, t.prefix, a)
		return true
	})
	t.buf.add(e)
	return t.next.Handle(ctx, r)
}

func (t *tee) WithAttrs(as []slog.Attr) slog.Handler {
	n := *t
	n.next = t.next.WithAttrs(as)
	n.attrs = append([]Attr(nil), t.attrs...)
	for _, a := range as {
		n.attrs = appendAttr(n.attrs, t.prefix, a)
	}
	return &n
}

func (t *tee) WithGroup(name string) slog.Handler {
	n := *t
	n.next = t.next.WithGroup(name)
	n.prefix = t.prefix + name + "."
	return &n
}

func appendAttr(dst []Attr, prefix string, a slog.Attr) []Attr {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		for _, g := range v.Group() {
			dst = appendAttr(dst, prefix+a.Key+".", g)
		}
		return dst
	}
	if a.Key == "" {
		return dst
	}
	return append(dst, Attr{Key: prefix + a.Key, Value: v.String()})
}
