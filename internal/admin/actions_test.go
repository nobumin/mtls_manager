package admin_test

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nobumin/mtls_manager/internal/admin"
	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/eab"
	"github.com/nobumin/mtls_manager/internal/logbuf"
	"github.com/nobumin/mtls_manager/internal/store"
	"github.com/nobumin/mtls_manager/internal/testca"
)

const operatorName = "op1.internal.example.com"

// startWithOperator は adminName（閲覧のみ）と operatorName（変更できる）の 2 人を入れる。
func startWithOperator(t *testing.T) *env {
	return start(t, func(c *config.CA) {
		c.Admin.AllowedClients = []string{adminName, operatorName}
		c.Admin.Operators = []string{operatorName}
	})
}

// noRedirect はリダイレクトを追わないクライアントにする（POST の結果の 303 を確かめるため）。
func noRedirect(c *http.Client) *http.Client {
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

var (
	csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	onceRe = regexp.MustCompile(`name="once" value="([^"]+)"`)
)

// formOf は画面に埋め込まれたトークン（CSRF と、発行フォームの使い捨てトークン）を取り出す。
func formOf(t *testing.T, c *http.Client, url string) (csrf, once string) {
	t.Helper()
	_, body := get(t, c, url)
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("%s にフォームのトークンが無い", url)
	}
	if o := onceRe.FindStringSubmatch(body); o != nil {
		once = o[1]
	}
	return m[1], once
}

func csrfOf(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	tok, _ := formOf(t, c, url)
	return tok
}

func post(t *testing.T, c *http.Client, u string, form url.Values, header map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

func auditFind(e *env, text string) []logbuf.Entry {
	return e.logs.Find(logbuf.Query{Text: text})
}

func TestViewerCannotChange(t *testing.T) {
	e := startWithOperator(t)
	base := "https://" + e.addr
	viewer := noRedirect(e.client(t, e.issuer, adminName))

	// 閲覧のみの管理者には、変更のフォームを出さない。
	for _, p := range []string{"/eab", "/certs"} {
		if _, body := get(t, viewer, base+p); strings.Contains(body, `method="post"`) {
			t.Errorf("%s: 閲覧のみの管理者に変更のフォームが出ている", p)
		}
	}
	// 他の管理者のトークンを盗んでも、閲覧のみの管理者は変更できない。
	token, once := formOf(t, e.client(t, e.issuer, operatorName), base+"/eab")
	for path, form := range map[string]url.Values{
		"/eab/create":   {"csrf": {token}, "once": {once}, "names": {"web2." + testca.Domain}},
		"/eab/revoke":   {"csrf": {token}, "kid": {e.eabKID}, "confirm": {"yes"}},
		"/certs/revoke": {"csrf": {token}, "serial": {"abc123"}, "reason": {"1"}, "confirm": {"yes"}},
	} {
		if res, _ := post(t, viewer, base+path, form, nil); res.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status = %d（403 のはず）", path, res.StatusCode)
		}
	}
	if f := e.userKeys(t); len(f) != 1 {
		t.Errorf("EAB 鍵が変わった: %d 件", len(f))
	}
	if c, _ := e.db.Cert("abc123"); c.Revoked {
		t.Error("証明書が失効した")
	}
	if len(auditFind(e, "変更の操作を拒否")) < 3 {
		t.Error("拒否が監査ログに残っていない")
	}
}

func TestOperatorCreatesAndRevokesEAB(t *testing.T) {
	e := startWithOperator(t)
	base := "https://" + e.addr
	op := noRedirect(e.client(t, e.issuer, operatorName))
	token, once := formOf(t, op, base+"/eab")
	createForm := url.Values{
		"csrf": {token}, "once": {once}, "names": {"web2." + testca.Domain + ",\n*.app." + testca.Domain}, "note": {"web2（<b>検証</b>）"},
	}

	// 発行: HMAC 鍵はこの応答にだけ載る。
	res, body := post(t, op, base+"/eab/create", createForm, map[string]string{"Origin": base, "Sec-Fetch-Site": "same-origin"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("発行: status = %d: %s", res.StatusCode, body)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Error("発行の応答がキャッシュされ得る")
	}
	f := e.userKeys(t)
	if len(f) != 2 {
		t.Fatalf("EAB 鍵が %d 件", len(f))
	}
	k := f[1]
	if !strings.Contains(body, k.HMAC) || !strings.Contains(body, k.KID) {
		t.Fatal("発行した HMAC 鍵・kid が表示されない")
	}
	if strings.Contains(body, "<b>検証</b>") {
		t.Error("メモがエスケープされていない")
	}
	if len(k.Names) != 2 || k.Note != "web2（<b>検証</b>）" {
		t.Errorf("鍵の内容が違う: %+v", k)
	}
	// 一覧には HMAC 鍵を出さない。監査ログにも HMAC 鍵を残さない。
	if _, list := get(t, op, base+"/eab"); strings.Contains(list, k.HMAC) || !strings.Contains(list, k.KID) {
		t.Error("一覧の表示が違う（HMAC 鍵が出ている、または kid が無い）")
	}
	if got := auditFind(e, "EAB 鍵を発行"); len(got) != 1 {
		t.Errorf("発行の監査ログ: %d 件", len(got))
	}
	if len(auditFind(e, k.HMAC)) != 0 {
		t.Error("HMAC 鍵がログに出ている")
	}

	// 発行の画面の再読み込み（同じフォームの再送信）では、もう 1 つ発行しない。
	res, body = post(t, op, base+"/eab/create", createForm, nil)
	if res.StatusCode != http.StatusConflict || !strings.Contains(body, "すでに行った") {
		t.Errorf("再送信: status = %d", res.StatusCode)
	}
	if len(e.userKeys(t)) != 2 {
		t.Fatal("再送信で鍵がもう 1 つ発行された")
	}
	// 使い捨てのトークンが無いフォームも受け付けない。
	noOnce := url.Values{"csrf": {token}, "names": {"web3." + testca.Domain}}
	if res, _ := post(t, op, base+"/eab/create", noOnce, nil); res.StatusCode != http.StatusBadRequest {
		t.Errorf("使い捨てのトークンなし: status = %d", res.StatusCode)
	}

	// 確認のチェックが無ければ取り消さない（状態は変わらないので redirect せず、その画面にエラーを出す）。
	res, body = post(t, op, base+"/eab/revoke", url.Values{"csrf": {token}, "kid": {k.KID}}, nil)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "確認のチェック") {
		t.Errorf("確認なしの取り消し: status = %d", res.StatusCode)
	}
	if len(e.userKeys(t)) != 2 {
		t.Fatal("確認なしで取り消された")
	}

	// 取り消し。
	res, _ = post(t, op, base+"/eab/revoke", url.Values{"csrf": {token}, "kid": {k.KID}, "confirm": {"yes"}}, nil)
	loc := res.Header.Get("Location")
	if res.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "done=eab-revoked") {
		t.Fatalf("取り消し: status = %d, Location = %s", res.StatusCode, loc)
	}
	if f := e.userKeys(t); len(f) != 1 || f[0].KID == k.KID {
		t.Fatal("取り消されていない")
	}
	if _, page := get(t, op, base+loc); !strings.Contains(page, "EAB 鍵 "+k.KID+" を取り消した") {
		t.Error("取り消しの結果が表示されない")
	}
	// 存在しない kid。
	if res, _ := post(t, op, base+"/eab/revoke", url.Values{"csrf": {token}, "kid": {k.KID}, "confirm": {"yes"}}, nil); res.StatusCode != http.StatusBadRequest {
		t.Errorf("存在しない kid の取り消し: status = %d", res.StatusCode)
	}
	// 名前が不正なら発行しない。
	_, once2 := formOf(t, op, base+"/eab")
	if res, _ := post(t, op, base+"/eab/create", url.Values{"csrf": {token}, "once": {once2}, "names": {"bad name!"}}, nil); res.StatusCode != http.StatusBadRequest || len(e.userKeys(t)) != 1 {
		t.Errorf("不正な名前で発行できた: status = %d", res.StatusCode)
	}
}

// 管理者の名前と重なるワイルドカードの EAB 鍵は発行しない（その鍵で管理者の証明書を取られないように）。
func TestCreateRejectsWildcardOverlappingAdmins(t *testing.T) {
	e := startWithOperator(t) // 管理者: admin1.internal.example.com、op1.internal.example.com
	base := "https://" + e.addr
	op := noRedirect(e.client(t, e.issuer, operatorName))
	token, _ := formOf(t, op, base+"/eab")
	for _, names := range []string{"*.internal.example.com", "web9.internal.example.com,*.internal.example.com"} {
		_, once := formOf(t, op, base+"/eab")
		res, body := post(t, op, base+"/eab/create", url.Values{"csrf": {token}, "once": {once}, "names": {names}}, nil)
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "管理者の名前") {
			t.Errorf("%s: status = %d", names, res.StatusCode)
		}
	}
	if len(e.userKeys(t)) != 1 {
		t.Fatal("管理者の名前と重なる鍵が発行された")
	}
	// 管理者の名前を完全一致で許可する鍵（管理者の証明書の取得用）は発行できる。
	_, once := formOf(t, op, base+"/eab")
	if res, _ := post(t, op, base+"/eab/create", url.Values{"csrf": {token}, "once": {once}, "names": {adminName}}, nil); res.StatusCode != http.StatusOK {
		t.Errorf("管理者の名前の鍵: status = %d", res.StatusCode)
	}
}

func TestOperatorRevokesCert(t *testing.T) {
	e := startWithOperator(t)
	base := "https://" + e.addr
	op := noRedirect(e.client(t, e.issuer, operatorName))
	token := csrfOf(t, op, base+"/certs")

	for name, tc := range map[string]struct {
		form   url.Values
		status int
	}{
		"不正な失効理由（2 = CA の鍵の漏えい は受け付けない）": {url.Values{"serial": {"abc123"}, "reason": {"2"}, "confirm": {"yes"}}, http.StatusBadRequest},
		"確認なし":      {url.Values{"serial": {"abc123"}, "reason": {"1"}}, http.StatusBadRequest},
		"不正なシリアル":   {url.Values{"serial": {"xyz"}, "reason": {"1"}, "confirm": {"yes"}}, http.StatusBadRequest},
		"存在しないシリアル": {url.Values{"serial": {"ffff"}, "reason": {"1"}, "confirm": {"yes"}}, http.StatusNotFound},
	} {
		tc.form.Set("csrf", token)
		if res, _ := post(t, op, base+"/certs/revoke", tc.form, nil); res.StatusCode != tc.status {
			t.Errorf("%s: status = %d（%d のはず）", name, res.StatusCode, tc.status)
		}
	}
	if c, _ := e.db.Cert("abc123"); c.Revoked {
		t.Fatal("失効してしまった")
	}
	// 失効（シリアルは大文字・コロン区切りでも受け付ける）。
	res, _ := post(t, op, base+"/certs/revoke", url.Values{"csrf": {token}, "serial": {"AB:C1:23"}, "reason": {"1"}, "confirm": {"yes"}}, nil)
	loc := res.Header.Get("Location")
	if res.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "done=cert-revoked") {
		t.Fatalf("失効: status = %d, Location = %s", res.StatusCode, loc)
	}
	c, err := e.db.Cert("abc123")
	if err != nil || !c.Revoked || c.Reason != 1 {
		t.Fatalf("失効していない: %+v %v", c, err)
	}
	if len(auditFind(e, "証明書を失効")) != 1 {
		t.Error("失効の監査ログが無い")
	}
	if _, page := get(t, op, base+loc); !strings.Contains(page, "証明書 abc123 を失効させた") {
		t.Error("失効の結果が表示されない")
	}
	// 二重の失効。
	if res, _ := post(t, op, base+"/certs/revoke", url.Values{"csrf": {token}, "serial": {"abc123"}, "reason": {"1"}, "confirm": {"yes"}}, nil); res.StatusCode != http.StatusConflict {
		t.Errorf("二重の失効: status = %d", res.StatusCode)
	}
	// 失効した証明書には失効のフォームを出さない。
	if _, body := get(t, op, base+"/certs"); strings.Contains(body, `name="serial" value="abc123"`) {
		t.Error("失効済みの証明書に失効のフォームが出ている")
	}
}

func TestCSRFProtection(t *testing.T) {
	e := startWithOperator(t)
	base := "https://" + e.addr
	op := noRedirect(e.client(t, e.issuer, operatorName))
	token, once := formOf(t, op, base+"/eab")
	form := func(tok string) url.Values {
		return url.Values{"csrf": {tok}, "once": {once}, "names": {"web2." + testca.Domain}}
	}

	cases := []struct {
		name   string
		form   url.Values
		header map[string]string
	}{
		{"トークンなし", url.Values{"once": {once}, "names": {"web2." + testca.Domain}}, nil},
		{"不正なトークン", form("x" + token), nil},
		{"他のサイト（Sec-Fetch-Site）", form(token), map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{"同じサイトの別オリジン（Sec-Fetch-Site）", form(token), map[string]string{"Sec-Fetch-Site": "same-site"}},
		{"他のサイト（Origin）", form(token), map[string]string{"Origin": "https://evil.example.com"}},
		{"Origin が null", form(token), map[string]string{"Origin": "null"}},
	}
	for _, tc := range cases {
		if res, _ := post(t, op, base+"/eab/create", tc.form, tc.header); res.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status = %d（403 のはず）", tc.name, res.StatusCode)
		}
	}
	if len(e.userKeys(t)) != 1 {
		t.Fatal("偽の操作で EAB 鍵が発行された")
	}
	// 変更は POST だけ（GET では何もしない）。
	if res, _ := get(t, op, base+"/eab/create?csrf="+url.QueryEscape(token)+"&names=web2."+testca.Domain); res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET で変更の URL に届いた: %d", res.StatusCode)
	}
}

// 結果の表示は決まった種類と書式の正しい引数だけ。URL に任意の文言を仕込んで表示させることはできない。
func TestFlashCannotBeSpoofed(t *testing.T) {
	e := startWithOperator(t)
	c := e.client(t, e.issuer, adminName)
	base := "https://" + e.addr
	for _, q := range []string{
		"error=" + url.QueryEscape("EAB 鍵ファイルが壊れています。HMAC 鍵を送ってください"),
		"ok=" + url.QueryEscape("証明書を失効させた"),
		"done=unknown&arg=abc",
		"done=cert-revoked&arg=" + url.QueryEscape("<script>alert(1)</script>"),
		"done=cert-revoked&arg=" + url.QueryEscape("abc を失効させた。HMAC 鍵を送ってください"),
		"done=eab-revoked&arg=" + url.QueryEscape("x y"),
	} {
		if _, body := get(t, c, base+"/eab?"+q); strings.Contains(body, `class="flash`) {
			t.Errorf("%s: 結果の表示が出た", q)
		}
	}
	if _, body := get(t, c, base+"/certs?done=cert-revoked&arg=abc123"); !strings.Contains(body, "証明書 abc123 を失効させた") {
		t.Error("正しい結果の表示が出ない")
	}
}

// 失効させた管理者の証明書・発行の記録が無い証明書では、管理画面に入れない。
func TestRevokedAdminCertRejected(t *testing.T) {
	e := startWithOperator(t)
	base := "https://" + e.addr
	c, serial := e.clientWithSerial(t, e.issuer, operatorName, true, "")
	if res, _ := get(t, c, base+"/"); res.StatusCode != http.StatusOK {
		t.Fatalf("失効前: status = %d", res.StatusCode)
	}
	if err := e.db.RevokeCert(serial, 1, nil); err != nil {
		t.Fatal(err)
	}
	if res, _ := get(t, c, base+"/eab"); res.StatusCode != http.StatusForbidden {
		t.Errorf("失効した証明書で入れた: status = %d", res.StatusCode)
	}
	if len(auditFind(e, "失効した証明書での接続を拒否")) == 0 {
		t.Error("失効した証明書の拒否が監査ログに残っていない")
	}
	// CA の鍵で作られていても、発行の記録が無い証明書は拒否する。
	c2, _ := e.clientWithSerial(t, e.issuer, adminName, false, "")
	if res, _ := get(t, c2, base+"/"); res.StatusCode != http.StatusForbidden {
		t.Errorf("発行の記録が無い証明書で入れた: status = %d", res.StatusCode)
	}
	if len(auditFind(e, "発行の記録が無い証明書での接続を拒否")) == 0 {
		t.Error("発行の記録が無い証明書の拒否が監査ログに残っていない")
	}
}

func TestOperatorsConfig(t *testing.T) {
	c := &config.CA{
		ExternalURL: "https://ca.example.com:8443", DataDir: "d", RootCert: "r", IntermediateCert: "i", IntermediateKey: "k", EABFile: "e",
		Policy: config.CAPolicy{AllowedDomains: []string{"example.com"}},
		Admin:  config.CAAdmin{Listen: "127.0.0.1:9443", AllowedClients: []string{"a.example.com"}, Operators: []string{"bad name"}},
	}
	if err := c.Complete(); err == nil || !strings.Contains(err.Error(), "admin.operators") {
		t.Fatalf("不正な operators が通った: %v", err)
	}
}

func TestNewRequiresRevokeAndWritableDir(t *testing.T) {
	iss := testca.NewIssuer(t, testca.Domain)
	dir := t.TempDir()
	eabPath := filepath.Join(dir, "eab.json")
	if err := eab.Update(eabPath, func(f *eab.File) error { _, err := f.Add([]string{"web1." + testca.Domain}, ""); return err }); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	eabStore, err := eab.NewStore(eabPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.CA{EABFile: eabPath, Admin: config.CAAdmin{AllowedClients: []string{adminName}, Operators: []string{adminName}}}
	opts := admin.Options{Config: cfg, Issuer: iss, DB: db, EAB: eabStore, Logs: logbuf.New(100)}
	if _, err := admin.New(opts); err == nil {
		t.Error("operators があるのに Revoke なしで作れた")
	}
	opts.Revoke = func(string, int) error { return nil }
	if _, err := admin.New(opts); err != nil {
		t.Fatalf("書き込めるディレクトリで作れない: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root では書き込み権限の確認ができない")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := admin.New(opts); err == nil || !strings.Contains(err.Error(), "書き込める") {
		t.Errorf("書き込めないディレクトリで作れた: %v", err)
	}
}

// ログインの時点でも、証明書を発行した EAB 鍵が今もその名前を完全一致で許可しているかを確かめる。
func TestAdminCertRejectedByEABKey(t *testing.T) {
	e := startWithOperator(t)
	base := "https://" + e.addr

	// サーバ用のワイルドカードの鍵で発行済みの証明書（例: 後から admin.allowed_clients を広げた場合）。
	var wildKID string
	if err := eab.Update(e.eabPath, func(f *eab.File) error {
		k, err := f.Add([]string{"*.internal.example.com"}, "サーバ群")
		wildKID = k.KID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	c, _ := e.clientWithSerial(t, e.issuer, operatorName, true, wildKID)
	if res, _ := get(t, c, base+"/"); res.StatusCode != http.StatusForbidden {
		t.Errorf("ワイルドカードの鍵で発行した証明書で入れた: status = %d", res.StatusCode)
	}
	if len(auditFind(e, "完全一致で許可していない EAB 鍵で発行した証明書での接続を拒否")) == 0 {
		t.Error("拒否が監査ログに残っていない")
	}

	// 完全一致の鍵で発行した証明書は入れるが、その鍵を取り消すとすぐに入れなくなる。
	c2, _ := e.clientWithSerial(t, e.issuer, adminName, true, "")
	if res, _ := get(t, c2, base+"/"); res.StatusCode != http.StatusOK {
		t.Fatalf("完全一致の鍵で発行した証明書で入れない: status = %d", res.StatusCode)
	}
	if err := eab.Update(e.eabPath, func(f *eab.File) error {
		f.Remove(e.adminKey(t, adminName))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if res, _ := get(t, c2, base+"/"); res.StatusCode != http.StatusForbidden {
		t.Errorf("取り消した EAB 鍵で発行した証明書で入れた: status = %d", res.StatusCode)
	}
	if len(auditFind(e, "取り消した EAB 鍵で発行した証明書での接続を拒否")) == 0 {
		t.Error("拒否が監査ログに残っていない")
	}
}
