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

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// csrfOf は画面に埋め込まれたトークンを取り出す。
func csrfOf(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	_, body := get(t, c, url)
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("%s にフォームのトークンが無い", url)
	}
	return m[1]
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

func loadEAB(t *testing.T, path string) *eab.File {
	t.Helper()
	f, err := eab.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return f
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
	token := csrfOf(t, e.client(t, e.issuer, operatorName), base+"/eab")
	for path, form := range map[string]url.Values{
		"/eab/create":   {"csrf": {token}, "names": {"web2." + testca.Domain}},
		"/eab/revoke":   {"csrf": {token}, "kid": {e.eabKID}, "confirm": {"yes"}},
		"/certs/revoke": {"csrf": {token}, "serial": {"abc123"}, "reason": {"1"}, "confirm": {"yes"}},
	} {
		if res, _ := post(t, viewer, base+path, form, nil); res.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status = %d（403 のはず）", path, res.StatusCode)
		}
	}
	if f := loadEAB(t, e.eabPath); len(f.Keys) != 1 {
		t.Errorf("EAB 鍵が変わった: %d 件", len(f.Keys))
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
	token := csrfOf(t, op, base+"/eab")

	// 発行: HMAC 鍵はこの応答にだけ載る。
	res, body := post(t, op, base+"/eab/create", url.Values{
		"csrf": {token}, "names": {"web2." + testca.Domain + ",\n*.app." + testca.Domain}, "note": {"web2（<b>検証</b>）"},
	}, map[string]string{"Origin": base, "Sec-Fetch-Site": "same-origin"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("発行: status = %d: %s", res.StatusCode, body)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Error("発行の応答がキャッシュされ得る")
	}
	f := loadEAB(t, e.eabPath)
	if len(f.Keys) != 2 {
		t.Fatalf("EAB 鍵が %d 件", len(f.Keys))
	}
	k := f.Keys[1]
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

	// 確認のチェックが無ければ取り消さない。
	res, _ = post(t, op, base+"/eab/revoke", url.Values{"csrf": {token}, "kid": {k.KID}}, nil)
	if res.StatusCode != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "error=") {
		t.Errorf("確認なしの取り消し: status = %d, Location = %s", res.StatusCode, res.Header.Get("Location"))
	}
	if len(loadEAB(t, e.eabPath).Keys) != 2 {
		t.Fatal("確認なしで取り消された")
	}

	// 取り消し。
	res, _ = post(t, op, base+"/eab/revoke", url.Values{"csrf": {token}, "kid": {k.KID}, "confirm": {"yes"}}, nil)
	loc := res.Header.Get("Location")
	if res.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "ok=") {
		t.Fatalf("取り消し: status = %d, Location = %s", res.StatusCode, loc)
	}
	if f := loadEAB(t, e.eabPath); len(f.Keys) != 1 || f.Keys[0].KID == k.KID {
		t.Fatal("取り消されていない")
	}
	if _, page := get(t, op, base+loc); !strings.Contains(page, "を取り消した") {
		t.Error("取り消しの結果が表示されない")
	}
	// 存在しない kid。
	res, _ = post(t, op, base+"/eab/revoke", url.Values{"csrf": {token}, "kid": {k.KID}, "confirm": {"yes"}}, nil)
	if !strings.Contains(res.Header.Get("Location"), "error=") {
		t.Error("存在しない kid の取り消しがエラーにならない")
	}
	// 名前が不正なら発行しない。
	res, _ = post(t, op, base+"/eab/create", url.Values{"csrf": {token}, "names": {"bad name!"}}, nil)
	if !strings.Contains(res.Header.Get("Location"), "error=") || len(loadEAB(t, e.eabPath).Keys) != 1 {
		t.Error("不正な名前で発行できた")
	}
}

func TestOperatorRevokesCert(t *testing.T) {
	e := startWithOperator(t)
	base := "https://" + e.addr
	op := noRedirect(e.client(t, e.issuer, operatorName))
	token := csrfOf(t, op, base+"/certs")

	// 不正な失効理由（2 = CA の鍵の漏えい は受け付けない）。
	res, _ := post(t, op, base+"/certs/revoke", url.Values{"csrf": {token}, "serial": {"abc123"}, "reason": {"2"}, "confirm": {"yes"}}, nil)
	if !strings.Contains(res.Header.Get("Location"), "error=") {
		t.Error("不正な失効理由が通った")
	}
	// 確認なし。
	res, _ = post(t, op, base+"/certs/revoke", url.Values{"csrf": {token}, "serial": {"abc123"}, "reason": {"1"}}, nil)
	if !strings.Contains(res.Header.Get("Location"), "error=") {
		t.Error("確認なしで失効できた")
	}
	if c, _ := e.db.Cert("abc123"); c.Revoked {
		t.Fatal("失効してしまった")
	}
	// 失効（シリアルは大文字・コロン区切りでも受け付ける）。
	res, _ = post(t, op, base+"/certs/revoke", url.Values{"csrf": {token}, "serial": {"AB:C1:23"}, "reason": {"1"}, "confirm": {"yes"}}, nil)
	if res.StatusCode != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "ok=") {
		t.Fatalf("失効: status = %d, Location = %s", res.StatusCode, res.Header.Get("Location"))
	}
	c, err := e.db.Cert("abc123")
	if err != nil || !c.Revoked || c.Reason != 1 {
		t.Fatalf("失効していない: %+v %v", c, err)
	}
	if len(auditFind(e, "証明書を失効")) != 1 {
		t.Error("失効の監査ログが無い")
	}
	// 二重の失効・存在しないシリアル。
	for _, serial := range []string{"abc123", "ffff"} {
		res, _ = post(t, op, base+"/certs/revoke", url.Values{"csrf": {token}, "serial": {serial}, "reason": {"1"}, "confirm": {"yes"}}, nil)
		if !strings.Contains(res.Header.Get("Location"), "error=") {
			t.Errorf("%s: エラーにならない", serial)
		}
	}
	// 失効した証明書には失効のフォームを出さない。
	if _, body := get(t, op, base+"/certs"); strings.Contains(body, `action="/certs/revoke"`) {
		t.Error("失効済みの証明書に失効のフォームが出ている")
	}
}

func TestCSRFProtection(t *testing.T) {
	e := startWithOperator(t)
	base := "https://" + e.addr
	op := noRedirect(e.client(t, e.issuer, operatorName))
	token := csrfOf(t, op, base+"/eab")
	form := func(tok string) url.Values {
		return url.Values{"csrf": {tok}, "names": {"web2." + testca.Domain}}
	}

	cases := []struct {
		name   string
		form   url.Values
		header map[string]string
	}{
		{"トークンなし", url.Values{"names": {"web2." + testca.Domain}}, nil},
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
	if len(loadEAB(t, e.eabPath).Keys) != 1 {
		t.Fatal("偽の操作で EAB 鍵が発行された")
	}
	// 変更は POST だけ（GET では何もしない）。
	if res, _ := get(t, op, base+"/eab/create?csrf="+url.QueryEscape(token)+"&names=web2."+testca.Domain); res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET で変更の URL に届いた: %d", res.StatusCode)
	}
}

// 結果の表示は決まったパラメータだけで、HTML は埋め込めない。
func TestFlashIsEscaped(t *testing.T) {
	e := startWithOperator(t)
	_, body := get(t, e.client(t, e.issuer, adminName), "https://"+e.addr+"/eab?error="+url.QueryEscape("<script>alert(1)</script>"))
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("結果の表示がエスケープされていない")
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
