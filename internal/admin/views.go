package admin

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nobumin/mtls_manager/internal/eab"
	"github.com/nobumin/mtls_manager/internal/logbuf"
	"github.com/nobumin/mtls_manager/internal/store"
)

const timeFormat = "2006-01-02 15:04:05 MST"

var funcs = template.FuncMap{
	"fmtTime": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Local().Format(timeFormat)
	},
	"join": strings.Join,
}

// remaining は残り期間を「12 日 3 時間」のような表記にする。
func remaining(until time.Time, now time.Time) string {
	d := until.Sub(now)
	if d <= 0 {
		return "期限切れ"
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	switch {
	case days > 0:
		return fmt.Sprintf("%d 日 %d 時間", days, hours)
	case hours > 0:
		return fmt.Sprintf("%d 時間 %d 分", hours, int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%d 分", int(d.Minutes()))
	}
}

type caCertView struct {
	Label     string
	Subject   string
	NotAfter  time.Time
	Remaining string
	Warn      bool
	Permitted []string
}

func newCACertView(label string, c *x509.Certificate, now time.Time, warnWithin time.Duration) caCertView {
	return caCertView{
		Label: label, Subject: c.Subject.String(), NotAfter: c.NotAfter, Remaining: remaining(c.NotAfter, now),
		Warn: c.NotAfter.Sub(now) < warnWithin, Permitted: c.PermittedDNSDomains,
	}
}

type dashboardView struct {
	CA             []caCertView
	Warnings       []string
	AllowedDomains []string
	Validity       time.Duration
	ExternalURL    string
	Started        time.Time
	Valid          int
	Revoked        int
	Pending        int
	Accounts       int
	EABKeys        int
	LastIssued     time.Time
	ExpiringSoon   int // 有効期間の残りが 1/3 を切ったまま、次の証明書が発行されていない名前の組
}

func (s *Server) dashboardData(*http.Request) (any, error) {
	now := time.Now()
	certs, err := s.db.Certs()
	if err != nil {
		return nil, err
	}
	accounts, err := s.db.Accounts()
	if err != nil {
		return nil, err
	}
	keys, err := s.eab.Keys()
	if err != nil {
		return nil, err
	}
	validity := s.cfg.Cert.Validity.D()
	v := dashboardView{
		CA: []caCertView{
			newCACertView("ルート CA", s.issuer.Root, now, 365*24*time.Hour),
			newCACertView("中間 CA", s.issuer.Cert, now, 30*24*time.Hour),
		},
		AllowedDomains: s.cfg.Policy.AllowedDomains, Validity: validity, ExternalURL: s.cfg.ExternalURL,
		Started: s.started, Accounts: len(accounts), EABKeys: len(keys),
	}
	if rem := s.issuer.Cert.NotAfter.Sub(now); rem < validity/2 {
		v.Warnings = append(v.Warnings, "中間 CA の有効期限が近いため、証明書を発行できない。中間 CA を更新すること")
	} else if rem < 30*24*time.Hour {
		v.Warnings = append(v.Warnings, "中間 CA の有効期限まで 30 日を切った。中間 CA を更新すること")
	}
	if s.issuer.Root.NotAfter.Sub(now) < 365*24*time.Hour {
		v.Warnings = append(v.Warnings, "ルート CA の有効期限まで 1 年を切った。ルート CA の入れ替えを計画すること")
	}
	v.Warnings = append(v.Warnings, s.federationWarnings(now)...)
	// 名前の組ごとに最新の有効な証明書を見て、更新が遅れているものを数える。
	latest := map[string]store.Cert{}
	for _, c := range certs {
		switch {
		case c.Pending && !c.Revoked:
			v.Pending++
			continue
		case c.Revoked:
			if c.NotAfter.After(now) {
				v.Revoked++
			}
			continue
		case c.NotAfter.After(now):
			v.Valid++
		}
		if c.Issued().After(v.LastIssued) {
			v.LastIssued = c.Issued()
		}
		key := strings.Join(c.Names, ",")
		if cur, ok := latest[key]; !ok || c.NotAfter.After(cur.NotAfter) {
			latest[key] = c
		}
	}
	for _, c := range latest {
		life := c.NotAfter.Sub(c.NotBefore)
		if c.NotAfter.After(now) && c.NotAfter.Sub(now) < life/3 {
			v.ExpiringSoon++
		}
	}
	if v.ExpiringSoon > 0 {
		v.Warnings = append(v.Warnings, fmt.Sprintf("更新が遅れている証明書が %d 件ある（有効期間の残りが 1/3 を切ったまま、次の証明書が発行されていない）。該当するサーバの mtls-agent を確認すること", v.ExpiringSoon))
	}
	return v, nil
}

type certRow struct {
	Serial    string
	Names     []string
	Issued    time.Time
	NotAfter  time.Time
	Status    string
	StatusCSS string
	Account   string
	EABNote   string
}

type certsView struct {
	Rows      []certRow
	Query     string
	All       bool
	Total     int
	Truncated bool
}

const maxCertRows = 1000

func (s *Server) certsData(r *http.Request) (any, error) {
	now := time.Now()
	certs, err := s.db.Certs()
	if err != nil {
		return nil, err
	}
	notes, err := s.accountNotes()
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	all := r.URL.Query().Get("all") == "1"
	slices.SortFunc(certs, func(a, b store.Cert) int { return b.Issued().Compare(a.Issued()) })
	v := certsView{Query: r.URL.Query().Get("q"), All: all}
	for _, c := range certs {
		row := certRow{Serial: c.Serial, Names: c.Names, Issued: c.Issued(), NotAfter: c.NotAfter, Account: c.AccountID, EABNote: notes[c.AccountID]}
		switch {
		case c.Pending && !c.Revoked:
			row.Status, row.StatusCSS = "未完了", "warn"
		case c.Revoked:
			row.Status, row.StatusCSS = "失効 "+c.RevokedAt.Local().Format(timeFormat), "bad"
		case !now.Before(c.NotAfter):
			row.Status, row.StatusCSS = "期限切れ", "muted"
		default:
			row.Status, row.StatusCSS = "有効（残り "+remaining(c.NotAfter, now)+"）", "ok"
		}
		if !all && row.StatusCSS == "muted" {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(c.Serial+" "+strings.Join(c.Names, " ")+" "+row.EABNote), q) {
			continue
		}
		v.Total++
		if len(v.Rows) >= maxCertRows {
			v.Truncated = true
			continue
		}
		v.Rows = append(v.Rows, row)
	}
	return v, nil
}

// accountNotes はアカウント ID から、結び付いた EAB 鍵のメモ（無ければ kid）への対応を返す。
func (s *Server) accountNotes() (map[string]string, error) {
	accounts, err := s.db.Accounts()
	if err != nil {
		return nil, err
	}
	keys, err := s.eab.Keys()
	if err != nil {
		return nil, err
	}
	byKID := map[string]eab.Key{}
	for _, k := range keys {
		byKID[k.KID] = k
	}
	out := map[string]string{}
	for _, a := range accounts {
		k, ok := byKID[a.EABKeyID]
		switch {
		case !ok:
			out[a.ID] = a.EABKeyID + "（取り消し済み）"
		case k.Note != "":
			out[a.ID] = k.Note
		default:
			out[a.ID] = k.KID
		}
	}
	return out, nil
}

type eabRow struct {
	KID        string
	Names      []string
	Note       string
	CreatedAt  time.Time
	Accounts   int
	LastIssued time.Time
}

type eabView struct {
	Rows []eabRow
	// Orphans は、鍵が取り消されたがアカウントが残っている kid（新しい証明書は取得できない）。
	Orphans []string
}

func (s *Server) eabData(*http.Request) (any, error) {
	keys, err := s.eab.Keys()
	if err != nil {
		return nil, err
	}
	accounts, err := s.db.Accounts()
	if err != nil {
		return nil, err
	}
	certs, err := s.db.Certs()
	if err != nil {
		return nil, err
	}
	accountKID := map[string]string{}
	count := map[string]int{}
	for _, a := range accounts {
		accountKID[a.ID] = a.EABKeyID
		count[a.EABKeyID]++
	}
	last := map[string]time.Time{}
	for _, c := range certs {
		kid := accountKID[c.AccountID]
		if !c.Pending && c.Issued().After(last[kid]) {
			last[kid] = c.Issued()
		}
	}
	v := eabView{}
	known := map[string]bool{}
	for _, k := range keys {
		known[k.KID] = true
		// HMAC 鍵（秘密情報）は表示しない。
		v.Rows = append(v.Rows, eabRow{KID: k.KID, Names: k.Names, Note: k.Note, CreatedAt: k.CreatedAt, Accounts: count[k.KID], LastIssued: last[k.KID]})
	}
	for kid := range count {
		if !known[kid] {
			v.Orphans = append(v.Orphans, kid)
		}
	}
	slices.Sort(v.Orphans)
	return v, nil
}

// handleLogsAPI は直近のログを JSON で返す（ログの画面が定期的に読み込む）。
func (s *Server) handleLogsAPI(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after, _ := strconv.ParseUint(q.Get("after"), 10, 64)
	var level slog.Level
	if l := q.Get("level"); l != "" {
		if err := level.UnmarshalText([]byte(l)); err != nil {
			http.Error(w, "level が不正", http.StatusBadRequest)
			return
		}
	} else {
		level = slog.LevelDebug
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	entries := s.logs.Find(logbuf.Query{After: after, MinLevel: level, Text: q.Get("q"), Limit: limit})
	type entryJSON struct {
		Seq   uint64        `json:"seq"`
		Time  string        `json:"time"`
		Level string        `json:"level"`
		Msg   string        `json:"msg"`
		Attrs []logbuf.Attr `json:"attrs"`
	}
	out := make([]entryJSON, 0, len(entries))
	for _, e := range entries {
		out = append(out, entryJSON{Seq: e.Seq, Time: e.Time.Local().Format(timeFormat), Level: e.Level.String(), Msg: e.Msg, Attrs: e.Attrs})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"entries": out})
}
