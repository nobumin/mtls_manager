package admin_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/federation"
	"github.com/nobumin/mtls_manager/internal/testca"
)

const operator2Name = "op2.internal.example.com"

// startFederation は連携版を有効にし、閲覧のみ（adminName）と変更できる 2 人（operatorName・operator2Name）を入れる。
func startFederation(t *testing.T) (*env, string) {
	t.Helper()
	fedFile := filepath.Join(t.TempDir(), "federation.json")
	e := start(t, func(c *config.CA) {
		c.Admin.AllowedClients = []string{adminName, operatorName, operator2Name}
		c.Admin.Operators = []string{operatorName, operator2Name}
		c.Federation.File = fedFile
	})
	return e, fedFile
}

func partnerRecordJSON(t *testing.T) (string, string) {
	t.Helper()
	b := testca.NewIssuer(t, "b.example.net")
	rec, err := federation.NewRecord(b.Root, []string{"b.example.net"}, "B 社 <script>", []string{"sec@b.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(rec)
	return string(data), rec.RootSHA256
}

// 取り込み → 申請（1 人目）→ 承認（別の管理者）→ 停止 → 削除 を、管理画面で行う。
func TestFederationWorkflowInAdminUI(t *testing.T) {
	e, fedFile := startFederation(t)
	base := "https://" + e.addr
	op1 := noRedirect(e.client(t, e.issuer, operatorName))
	op2 := noRedirect(e.client(t, e.issuer, operator2Name))
	tok1, tok2 := csrfOf(t, op1, base+"/federation"), csrfOf(t, op2, base+"/federation")
	record, fp := partnerRecordJSON(t)

	res, _ := post(t, op1, base+"/federation/import", url.Values{"csrf": {tok1}, "id": {"b-corp"}, "record": {record}}, nil)
	if res.StatusCode != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "done=fed-imported") {
		t.Fatalf("取り込み: status = %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if _, page := get(t, op1, base+"/federation"); !strings.Contains(page, "b-corp") || strings.Contains(page, "<script>") || !strings.Contains(page, "未検証") {
		t.Error("取り込んだ連携先の表示が違う（未検証の表示・エスケープ）")
	}

	// 申請: 一部だけの指紋・照合の相手なしは拒否する。
	for name, form := range map[string]url.Values{
		"一部だけの指紋": {"csrf": {tok1}, "id": {"b-corp"}, "fingerprint": {fp[:40]}, "compared_with": {"電話"}},
		"照合の相手なし": {"csrf": {tok1}, "id": {"b-corp"}, "fingerprint": {fp}},
	} {
		if res, _ := post(t, op1, base+"/federation/request", form, nil); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d", name, res.StatusCode)
		}
	}
	res, _ = post(t, op1, base+"/federation/request", url.Values{"csrf": {tok1}, "id": {"b-corp"}, "fingerprint": {fp}, "compared_with": {"契約書記載の窓口、電話"}}, nil)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("申請: status = %d", res.StatusCode)
	}
	// 概要に承認待ちの警告が出る。
	if _, page := get(t, op2, base+"/"); !strings.Contains(page, "承認を待っている") {
		t.Error("概要に承認待ちの警告が出ない")
	}
	// 申請者は承認できない（承認のフォームも出さない）。
	if _, page := get(t, op1, base+"/federation"); strings.Contains(page, `action="/federation/approve"`) {
		t.Error("申請者に承認のフォームが出ている")
	}
	if res, body := post(t, op1, base+"/federation/approve", url.Values{"csrf": {tok1}, "id": {"b-corp"}, "fingerprint": {fp}, "confirm": {"yes"}}, nil); res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "別の管理者") {
		t.Errorf("申請者が承認できた: status = %d", res.StatusCode)
	}
	// 別の管理者: 指紋が違う・確認なしは拒否、正しければ承認。
	if res, _ := post(t, op2, base+"/federation/approve", url.Values{"csrf": {tok2}, "id": {"b-corp"}, "fingerprint": {"00" + fp[2:]}, "confirm": {"yes"}}, nil); res.StatusCode != http.StatusBadRequest {
		t.Errorf("違う指紋で承認できた: status = %d", res.StatusCode)
	}
	if res, _ := post(t, op2, base+"/federation/approve", url.Values{"csrf": {tok2}, "id": {"b-corp"}, "fingerprint": {fp}}, nil); res.StatusCode != http.StatusBadRequest {
		t.Errorf("確認なしで承認できた: status = %d", res.StatusCode)
	}
	res, _ = post(t, op2, base+"/federation/approve", url.Values{"csrf": {tok2}, "id": {"b-corp"}, "fingerprint": {fp}, "confirm": {"yes"}}, nil)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("承認: status = %d", res.StatusCode)
	}
	f, err := federation.Load(fedFile)
	if err != nil {
		t.Fatal(err)
	}
	p := f.Find("b-corp")
	if p.State != federation.StateActive || p.RequestedBy != operatorName || p.ApprovedBy != operator2Name ||
		p.RequestedVia != federation.ViaAdmin || p.ApprovedVia != federation.ViaAdmin {
		t.Fatalf("承認の記録が違う: %+v", p)
	}
	if len(auditFind(e, "連携を承認した")) != 1 {
		t.Error("承認の監査ログが無い")
	}

	// 停止（1 人で即時）→ 削除。
	if res, _ := post(t, op1, base+"/federation/remove", url.Values{"csrf": {tok1}, "id": {"b-corp"}, "confirm": {"yes"}}, nil); res.StatusCode != http.StatusBadRequest {
		t.Errorf("有効な連携先を停止せずに消せた: status = %d", res.StatusCode)
	}
	if res, _ := post(t, op1, base+"/federation/suspend", url.Values{"csrf": {tok1}, "id": {"b-corp"}, "reason": {"侵害の疑い"}, "confirm": {"yes"}}, nil); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("停止: status = %d", res.StatusCode)
	}
	if f, _ := federation.Load(fedFile); f.Find("b-corp").State != federation.StateSuspended {
		t.Fatal("停止されていない")
	}
	if res, _ := post(t, op1, base+"/federation/remove", url.Values{"csrf": {tok1}, "id": {"b-corp"}, "confirm": {"yes"}}, nil); res.StatusCode != http.StatusSeeOther {
		t.Errorf("削除: status = %d", res.StatusCode)
	}
	if f, _ := federation.Load(fedFile); f.Find("b-corp") != nil {
		t.Error("削除されていない")
	}
}

// 閲覧のみの管理者は、連携先を変更できない。自分の連携情報の書き出しはできる。
func TestFederationViewer(t *testing.T) {
	e, _ := startFederation(t)
	base := "https://" + e.addr
	viewer := noRedirect(e.client(t, e.issuer, adminName))
	op1 := e.client(t, e.issuer, operatorName)
	record, _ := partnerRecordJSON(t)
	tok := csrfOf(t, op1, base+"/federation")
	if _, page := get(t, viewer, base+"/federation"); strings.Contains(page, `method="post"`) {
		t.Error("閲覧のみの管理者に変更のフォームが出ている")
	}
	if res, _ := post(t, viewer, base+"/federation/import", url.Values{"csrf": {tok}, "id": {"b-corp"}, "record": {record}}, nil); res.StatusCode != http.StatusForbidden {
		t.Errorf("閲覧のみの管理者が取り込めた: status = %d", res.StatusCode)
	}
	res, body := get(t, viewer, base+"/federation/export?org=A")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("書き出し: status = %d", res.StatusCode)
	}
	rec, root, err := federation.ParseRecord([]byte(body))
	if err != nil || !root.Equal(e.issuer.Root) || rec.Domains[0] != testca.Domain || rec.Organization != "A" {
		t.Fatalf("書き出した連携情報が違う: %+v %v", rec, err)
	}
}

// 連携版が無効なら、画面は案内だけで、変更の操作は 404。
func TestFederationDisabled(t *testing.T) {
	e := startWithOperator(t)
	base := "https://" + e.addr
	op := noRedirect(e.client(t, e.issuer, operatorName))
	if _, page := get(t, op, base+"/federation"); !strings.Contains(page, "有効でない") {
		t.Error("無効の案内が出ない")
	}
	tok := csrfOf(t, op, base+"/eab")
	if res, _ := post(t, op, base+"/federation/import", url.Values{"csrf": {tok}, "id": {"x"}, "record": {"{}"}}, nil); res.StatusCode != http.StatusNotFound {
		t.Errorf("無効なのに status = %d", res.StatusCode)
	}
	if res, _ := get(t, op, base+"/federation/export"); res.StatusCode != http.StatusNotFound {
		t.Errorf("無効なのに書き出せた: %d", res.StatusCode)
	}
}

// 連携の有効期限が 30 日を切ったら、概要と「連携」画面で警告する。
func TestFederationExpiryWarning(t *testing.T) {
	e, fedFile := startFederation(t)
	base := "https://" + e.addr
	b := testca.NewIssuer(t, "b.example.net")
	rec, _ := federation.NewRecord(b.Root, []string{"b.example.net"}, "", nil)
	fp := federation.Fingerprint(b.Root)
	now := time.Now()
	if err := federation.Update(fedFile, func(f *federation.File) error {
		if err := f.Import("b-corp", rec, b.Root, now, federation.ByCLI("alice")); err != nil {
			return err
		}
		o := federation.RequestOptions{Fingerprint: fp, ComparedWith: "電話", Validity: 10 * 24 * time.Hour, By: federation.ByCLI("alice")}
		if err := f.Request("b-corp", o, []string{testca.Domain}, now); err != nil {
			return err
		}
		return f.Approve("b-corp", fp, federation.ByCLI("bob"), []string{testca.Domain}, now)
	}); err != nil {
		t.Fatal(err)
	}
	c := e.client(t, e.issuer, adminName)
	if _, page := get(t, c, base+"/"); !strings.Contains(page, "30 日を切った") {
		t.Error("概要に有効期限の警告が出ない")
	}
	if _, page := get(t, c, base+"/federation"); !strings.Contains(page, "row-warn") || !strings.Contains(page, "自己申告") {
		t.Error("「連携」画面に警告、または CLI（自己申告）の表示が出ない")
	}
}
