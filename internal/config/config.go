// Package config は CA・エージェントの設定ファイル（YAML）を読む。
//
// 設定ファイルには秘密情報そのものを書かず、鍵などはファイルのパスで指す。
// 実運用の設定ファイルはリポジトリの外（/etc/mtls-ca など）に置く。
package config

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Duration は "24h" のような Go の書式に加えて "7d"（日）・"10y"（365 日単位の年）を受け付ける。
type Duration time.Duration

// ParseDuration は Duration の書式を解釈する。
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "y": 365 * 24 * time.Hour} {
		if num, ok := strings.CutSuffix(s, suffix); ok {
			n, err := strconv.Atoi(num)
			if err != nil || n < 0 {
				return 0, fmt.Errorf("期間 %q を解釈できない", s)
			}
			return time.Duration(n) * unit, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("期間 %q を解釈できない（例: 24h, 7d, 10y）", s)
	}
	return d, nil
}

// UnmarshalYAML は YAML の文字列から読む。
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// D は time.Duration を返す。
func (d Duration) D() time.Duration { return time.Duration(d) }

// NewLogger は設定に従ったロガーを作る。
func (l Log) NewLogger(w io.Writer) *slog.Logger {
	var level slog.Level
	_ = level.UnmarshalText([]byte(l.Level))
	opts := &slog.HandlerOptions{Level: level}
	if l.Format == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// load は未知のキーをエラーにして読む（綴り間違いを黙って無視しない）。
func load(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
