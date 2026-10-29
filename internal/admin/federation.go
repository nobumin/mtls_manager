package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nobumin/mtls_manager/internal/federation"
	"github.com/nobumin/mtls_manager/mtls"
)

// 連携版の「連携」画面（設計 7.・10.。段階 2）。
//   - 取り込み・承認の申請・承認・停止・削除を、admin.operators の管理者が行う
//   - 操作した管理者の名前は mTLS の証明書で確かめたもの（CLI の -by のような自己申告ではない）
//   - 承認は申請者と別の管理者が行い、申請と承認の両方で指紋の全体を入力する
//   - 連携の有効期限が近いもの・承認待ちのものは、この画面と概要に警告を出す

// fedWarnBefore は連携の有効期限の警告を出し始める残り期間。
const fedWarnBefore = 30 * 24 * time.Hour

type fedView struct {
	Enabled        bool
	File           string
	OwnScope       []string
	OwnFingerprint string
	Partners       []fedRow
	Me             string
}

type fedRow struct {
	federation.Partner
	FingerprintGroups string
	ExpiresWarn       bool
	// CanApprove は、この管理者が承認できる（申請者と別の人）ことを表す。
	CanApprove bool
	// SelfDeclared は、申請か承認が CLI（名前が自己申告）で行われたことを表す。
	SelfDeclared bool
}

func (s *Server) federationEnabled() bool { return s.cfg.Federation.File != "" && s.fed != nil }

// federationData は「連携」画面のデータ。
func (s *Server) federationData(r *http.Request) (any, error) {
	v := fedView{Enabled: s.federationEnabled(), Me: mtls.PeerNames(r.TLS)[0]}
	if !v.Enabled {
		return v, nil
	}
	v.File, v.OwnScope, v.OwnFingerprint = s.cfg.Federation.File, s.fed.OwnScope(), federation.Fingerprint(s.issuer.Root)
	f, err := federation.LoadOrEmpty(s.cfg.Federation.File)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for _, p := range f.Partners {
		row := fedRow{Partner: p, FingerprintGroups: fingerprintGroups(p.RootSHA256)}
		row.ExpiresWarn = p.State == federation.StateActive && p.Expires.Sub(now) < fedWarnBefore
		row.CanApprove = p.State == federation.StateRequested && p.RequestedBy != v.Me
		row.SelfDeclared = p.RequestedVia == federation.ViaCLI || p.ApprovedVia == federation.ViaCLI
		v.Partners = append(v.Partners, row)
	}
	return v, nil
}

// federationWarnings は概要に出す警告（承認待ち・有効期限が近い・切れた連携）。
func (s *Server) federationWarnings(now time.Time) []string {
	if !s.federationEnabled() {
		return nil
	}
	f, err := federation.LoadOrEmpty(s.cfg.Federation.File)
	if err != nil {
		return []string{"連携情報のファイルを読めない: " + err.Error()}
	}
	var out []string
	for _, p := range f.Partners {
		switch {
		case p.State == federation.StateRequested:
			out = append(out, fmt.Sprintf("連携先 %s の承認を待っている（申請者 %s とは別の管理者が「連携」画面で承認する）", p.ID, p.RequestedBy))
		case p.State == federation.StateActive && !now.Before(p.Expires):
			out = append(out, fmt.Sprintf("連携先 %s の有効期限が切れた（トラストバンドルに入っていない）。照合と承認をやり直す", p.ID))
		case p.State == federation.StateActive && p.Expires.Sub(now) < fedWarnBefore:
			out = append(out, fmt.Sprintf("連携先 %s の有効期限まで 30 日を切った（%s）。照合と承認をやり直す", p.ID, p.Expires.Local().Format(timeFormat)))
		}
	}
	return out
}

// fingerprintGroups は指紋を 4 桁ずつ区切る（読み上げやすくするため）。
func fingerprintGroups(fp string) string {
	n := federation.NormalizeFingerprint(fp)
	var b strings.Builder
	for i := 0; i < len(n); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(n[i:min(i+4, len(n))])
	}
	return b.String()
}

// fedUpdate は連携情報のファイルを、ロックの下で書き換える。
func (s *Server) fedUpdate(fn func(*federation.File) error) error {
	return federation.Update(s.cfg.Federation.File, fn)
}

// checkFedPost は変更の操作の共通の確認（権限・CSRF・連携版が有効か・識別子）。
func (s *Server) checkFedPost(w http.ResponseWriter, r *http.Request, action string) (admin, id string, ok bool) {
	admin, ok = s.checkPost(w, r, action)
	if !ok {
		return "", "", false
	}
	if !s.federationEnabled() {
		http.Error(w, "連携版が有効でない（federation.file）", http.StatusNotFound)
		return "", "", false
	}
	id = strings.TrimSpace(r.PostForm.Get("id"))
	if err := federation.ValidateID(id); err != nil {
		s.fail(w, r, "federation", http.StatusBadRequest, err.Error())
		return "", "", false
	}
	return admin, id, true
}

func (s *Server) handleFedImport(w http.ResponseWriter, r *http.Request) {
	admin, id, ok := s.checkFedPost(w, r, "federation_import")
	if !ok {
		return
	}
	rec, root, err := federation.ParseRecord([]byte(r.PostForm.Get("record")))
	if err != nil {
		s.fail(w, r, "federation", http.StatusBadRequest, err.Error())
		return
	}
	if err := s.fedUpdate(func(f *federation.File) error {
		return f.Import(id, rec, root, time.Now(), federation.ByAdmin(admin))
	}); err != nil {
		s.fail(w, r, "federation", http.StatusBadRequest, "取り込めない: "+err.Error())
		return
	}
	s.log.Info("管理画面: 連携先を取り込んだ", "category", "audit", "admin", admin, "partner", id, "fingerprint", federation.Fingerprint(root), "declared_domains", rec.Domains)
	redirectDone(w, r, "/federation", "fed-imported", id)
}

func (s *Server) handleFedRequest(w http.ResponseWriter, r *http.Request) {
	admin, id, ok := s.checkFedPost(w, r, "federation_request")
	if !ok {
		return
	}
	o := federation.RequestOptions{
		Fingerprint: r.PostForm.Get("fingerprint"), ComparedWith: strings.TrimSpace(r.PostForm.Get("compared_with")),
		Domains: strings.FieldsFunc(r.PostForm.Get("domains"), func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\r' }),
		By:      federation.ByAdmin(admin),
	}
	if d := strings.TrimSpace(r.PostForm.Get("validity_days")); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 1 || n > 730 {
			s.fail(w, r, "federation", http.StatusBadRequest, "連携の有効期限は 1〜730 日")
			return
		}
		o.Validity = time.Duration(n) * 24 * time.Hour
	}
	if len(o.ComparedWith) > 300 {
		s.fail(w, r, "federation", http.StatusBadRequest, "照合した相手と経路は 300 文字まで")
		return
	}
	if err := s.fedUpdate(func(f *federation.File) error { return f.Request(id, o, s.fed.OwnScope(), time.Now()) }); err != nil {
		s.log.Warn("管理画面: 連携の承認を申請できない", "category", "audit", "admin", admin, "partner", id, "err", err)
		s.fail(w, r, "federation", http.StatusBadRequest, "申請できない: "+err.Error())
		return
	}
	s.log.Info("管理画面: 連携の承認を申請した", "category", "audit", "admin", admin, "partner", id, "compared_with", o.ComparedWith, "domains", o.Domains)
	redirectDone(w, r, "/federation", "fed-requested", id)
}

func (s *Server) handleFedApprove(w http.ResponseWriter, r *http.Request) {
	admin, id, ok := s.checkFedPost(w, r, "federation_approve")
	if !ok {
		return
	}
	if !requireConfirm(r) {
		s.fail(w, r, "federation", http.StatusBadRequest, "確認のチェックを入れてから承認する")
		return
	}
	err := s.fedUpdate(func(f *federation.File) error {
		return f.Approve(id, r.PostForm.Get("fingerprint"), federation.ByAdmin(admin), s.fed.OwnScope(), time.Now())
	})
	if err != nil {
		s.log.Warn("管理画面: 連携を承認できない", "category", "audit", "admin", admin, "partner", id, "err", err)
		s.fail(w, r, "federation", http.StatusBadRequest, "承認できない: "+err.Error())
		return
	}
	s.log.Warn("管理画面: 連携を承認した（トラストバンドルに入る）", "category", "audit", "admin", admin, "partner", id)
	redirectDone(w, r, "/federation", "fed-approved", id)
}

func (s *Server) handleFedSuspend(w http.ResponseWriter, r *http.Request) {
	admin, id, ok := s.checkFedPost(w, r, "federation_suspend")
	if !ok {
		return
	}
	if !requireConfirm(r) {
		s.fail(w, r, "federation", http.StatusBadRequest, "確認のチェックを入れてから停止する")
		return
	}
	reason := strings.TrimSpace(r.PostForm.Get("reason"))
	if len(reason) > 300 {
		s.fail(w, r, "federation", http.StatusBadRequest, "理由は 300 文字まで")
		return
	}
	if err := s.fedUpdate(func(f *federation.File) error { return f.Suspend(id, federation.ByAdmin(admin), reason, time.Now()) }); err != nil {
		s.fail(w, r, "federation", http.StatusBadRequest, "停止できない: "+err.Error())
		return
	}
	s.log.Warn("管理画面: 連携を停止した", "category", "audit", "admin", admin, "partner", id, "reason", reason)
	redirectDone(w, r, "/federation", "fed-suspended", id)
}

func (s *Server) handleFedRemove(w http.ResponseWriter, r *http.Request) {
	admin, id, ok := s.checkFedPost(w, r, "federation_remove")
	if !ok {
		return
	}
	if !requireConfirm(r) {
		s.fail(w, r, "federation", http.StatusBadRequest, "確認のチェックを入れてから消す")
		return
	}
	if err := s.fedUpdate(func(f *federation.File) error { return f.Remove(id) }); err != nil {
		s.fail(w, r, "federation", http.StatusBadRequest, "消せない: "+err.Error())
		return
	}
	s.log.Warn("管理画面: 連携先を消した", "category", "audit", "admin", admin, "partner", id)
	redirectDone(w, r, "/federation", "fed-removed", id)
}

// handleFedExport は自分の連携情報（公開情報のみ）を書き出す。閲覧のみの管理者も使える。
func (s *Server) handleFedExport(w http.ResponseWriter, r *http.Request) {
	if !s.federationEnabled() {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	org := truncateRunes(strings.TrimSpace(q.Get("org")), 200)
	var contacts []string
	for _, c := range strings.FieldsFunc(q.Get("contacts"), func(c rune) bool { return c == ',' || c == ' ' }) {
		contacts = append(contacts, truncateRunes(c, 200))
	}
	rec, err := federation.NewRecord(s.issuer.Root, s.fed.OwnScope(), org, contacts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="federation-record.json"`)
	_, _ = w.Write(append(data, '\n'))
}

// checkFederationWritable は、管理画面から連携情報のファイルを書き換えられることを確かめる（起動時）。
func checkFederationWritable(path string) error {
	if err := checkWritable(filepath.Dir(path)); err != nil {
		return fmt.Errorf("federation.file のディレクトリに mtls-ca が書き込める必要がある: %w", err)
	}
	errCheck := errors.New("check")
	if err := federation.Update(path, func(*federation.File) error { return errCheck }); !errors.Is(err, errCheck) {
		return fmt.Errorf("mtls-ca が federation.file を更新できる必要がある: %w", err)
	}
	return nil
}

// truncateRunes は s を n 文字までにする。
func truncateRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
