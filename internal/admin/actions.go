package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nobumin/mtls_manager/internal/eab"
	"github.com/nobumin/mtls_manager/internal/i18n"
	"github.com/nobumin/mtls_manager/internal/names"
	"github.com/nobumin/mtls_manager/internal/store"
	"github.com/nobumin/mtls_manager/mtls"
)

// 変更の操作（EAB 鍵の発行・取り消し、証明書の失効）。
//
// mTLS ではブラウザが他のサイトからのリクエストにも証明書を自動で付けるので、次の 3 つで偽の操作（CSRF）を防ぐ。
//   - フォームに埋め込んだトークン（管理者ごと。CA の起動ごとに変わる鍵で作る）
//   - Sec-Fetch-Site / Origin ヘッダが同じサイトからの送信であること
//   - POST のみ（閲覧の GET では何も変えない）

func (s *Server) isOperator(admin string) bool {
	return names.MatchAny(s.operators, admin)
}

// csrfToken は管理者ごとのトークンを返す（管理者の名前の HMAC。CA を再起動すると変わる）。
func (s *Server) csrfToken(admin string) string {
	m := hmac.New(sha256.New, s.csrfKey)
	m.Write([]byte(admin))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// checkPost は変更の操作のリクエストを確かめ、問題があれば応答して ok=false を返す。
func (s *Server) checkPost(w http.ResponseWriter, r *http.Request, action string) (admin string, ok bool) {
	admin = mtls.PeerNames(r.TLS)[0]
	reject := func(status int, reason string) (string, bool) {
		s.log.Warn(i18n.T("管理画面: 変更の操作を拒否", "admin UI: refused a change operation"), "category", "audit", "admin", admin, "action", action, "reason", reason, "remote", r.RemoteAddr)
		http.Error(w, reason, status)
		return admin, false
	}
	if !s.isOperator(admin) {
		return reject(http.StatusForbidden, i18n.T("この管理者には変更の権限がない（admin.operators）", "this administrator has no permission to make changes (admin.operators)"))
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return reject(http.StatusForbidden, i18n.T("他のサイトからの送信は受け付けない", "submissions from other sites are not accepted"))
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host {
			return reject(http.StatusForbidden, i18n.T("他のサイトからの送信は受け付けない", "submissions from other sites are not accepted"))
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		return reject(http.StatusBadRequest, i18n.T("フォームを解釈できない", "cannot parse the form"))
	}
	if !hmac.Equal([]byte(r.PostForm.Get("csrf")), []byte(s.csrfToken(admin))) {
		return reject(http.StatusForbidden, i18n.T("フォームのトークンが無効（画面を開き直してやり直す）", "invalid form token (reopen the page and try again)"))
	}
	return admin, true
}

func requireConfirm(r *http.Request) bool { return r.PostForm.Get("confirm") == "yes" }

// onceTokens は EAB 鍵の発行フォームの使い捨てトークン。発行の画面の再読み込み（フォームの再送信）で
// 鍵がもう 1 つ発行されないよう、使ったトークンを覚えておく。
type onceTokens struct {
	mu   sync.Mutex
	used map[string]time.Time
}

const onceTTL = 24 * time.Hour

func newOnce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// use はトークンを使用済みにする。すでに使われていれば false。
func (o *onceTokens) use(tok string, now time.Time) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.used == nil {
		o.used = map[string]time.Time{}
	}
	for k, t := range o.used {
		if now.Sub(t) > onceTTL {
			delete(o.used, k)
		}
	}
	if _, ok := o.used[tok]; ok {
		return false
	}
	o.used[tok] = now
	return true
}

var onceRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// handleEABCreate は EAB 鍵を発行し、その HMAC 鍵を一度だけ表示する。
func (s *Server) handleEABCreate(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.checkPost(w, r, "eab_create")
	if !ok {
		return
	}
	once := r.PostForm.Get("once")
	if !onceRe.MatchString(once) {
		s.fail(w, r, "eab", http.StatusBadRequest, i18n.T("フォームが古い。画面を開き直してやり直す", "the form is outdated; reopen the page and try again"))
		return
	}
	patterns := strings.FieldsFunc(r.PostForm.Get("names"), func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\r' || c == '\t' })
	note := strings.TrimSpace(r.PostForm.Get("note"))
	if utf8.RuneCountInString(note) > 200 {
		s.fail(w, r, "eab", http.StatusBadRequest, i18n.T("メモは 200 文字まで", "the note must be at most 200 characters"))
		return
	}
	if !s.once.use(once, time.Now()) {
		s.log.Warn(i18n.T("管理画面: EAB 鍵の発行の再送信を無視", "admin UI: ignored a resubmitted EAB key issuance"), "category", "audit", "admin", admin)
		s.fail(w, r, "eab", http.StatusConflict, i18n.T("この発行はすでに行った（画面の再読み込みによる再送信は無視した）。発行した鍵は一覧で確かめる", "this issuance was already done (a resubmission from reloading the page was ignored); check the issued key in the list"))
		return
	}
	var created eab.Key
	err := eab.Update(s.cfg.EABFile, func(f *eab.File) error {
		var err error
		if created, err = f.Add(patterns, note); err != nil {
			return err
		}
		// 管理者の名前と重なるワイルドカードは受け付けない（その鍵で管理者の証明書を取られないように）。
		if ov := created.WildcardOverlaps(s.cfg.Admin.AllowedClients); len(ov) > 0 {
			return fmt.Errorf(i18n.T("ワイルドカード %s が管理者の名前（admin.allowed_clients）と重なる。管理者の名前はサーバと別のサブドメインにする", "wildcard %s overlaps an administrator name (admin.allowed_clients); put administrator names in a subdomain separate from servers"), strings.Join(ov, ", "))
		}
		return nil
	})
	if err != nil {
		s.log.Warn(i18n.T("管理画面: EAB 鍵を発行できない", "admin UI: cannot issue an EAB key"), "category", "audit", "admin", admin, "err", err)
		s.fail(w, r, "eab", http.StatusBadRequest, i18n.T("EAB 鍵を発行できない: ", "cannot issue the EAB key: ")+err.Error())
		return
	}
	s.log.Info(i18n.T("管理画面: EAB 鍵を発行", "admin UI: issued an EAB key"), "category", "audit", "admin", admin, "eab_kid", created.KID, "names", created.Names, "note", created.Note)
	// HMAC 鍵は秘密情報。この応答にだけ載せ、ログや URL には出さない（Cache-Control: no-store）。
	s.render(w, r, http.StatusOK, "eab_created", created, "", false)
}

// handleEABRevoke は EAB 鍵を取り消す。その鍵で登録したサーバは、以後新しい証明書を取得できない。
func (s *Server) handleEABRevoke(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.checkPost(w, r, "eab_revoke")
	if !ok {
		return
	}
	kid := r.PostForm.Get("kid")
	if !kidRe.MatchString(kid) {
		s.fail(w, r, "eab", http.StatusBadRequest, i18n.T("kid が不正", "invalid kid"))
		return
	}
	if !requireConfirm(r) {
		s.fail(w, r, "eab", http.StatusBadRequest, i18n.T("確認のチェックを入れてから取り消す", "tick the confirmation box before revoking"))
		return
	}
	err := eab.Update(s.cfg.EABFile, func(f *eab.File) error {
		if !f.Remove(kid) {
			return errors.New(i18n.T("見つからない", "not found"))
		}
		return nil
	})
	if err != nil {
		s.log.Warn(i18n.T("管理画面: EAB 鍵を取り消せない", "admin UI: cannot revoke an EAB key"), "category", "audit", "admin", admin, "eab_kid", kid, "err", err)
		s.fail(w, r, "eab", http.StatusBadRequest, fmt.Sprintf(i18n.T("EAB 鍵 %s を取り消せない: %v", "cannot revoke EAB key %s: %v"), kid, err))
		return
	}
	s.log.Warn(i18n.T("管理画面: EAB 鍵を取り消し", "admin UI: revoked an EAB key"), "category", "audit", "admin", admin, "eab_kid", kid)
	redirectDone(w, r, "/eab", "eab-revoked", kid)
}

// handleCertRevoke は証明書を失効させる。
func (s *Server) handleCertRevoke(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.checkPost(w, r, "cert_revoke")
	if !ok {
		return
	}
	reason, err := strconv.Atoi(r.PostForm.Get("reason"))
	if err != nil || !store.ValidRevocationReason(reason) {
		s.fail(w, r, "certs", http.StatusBadRequest, i18n.T("失効理由が不正", "invalid revocation reason"))
		return
	}
	n, okSerial := new(big.Int).SetString(strings.ReplaceAll(strings.ToLower(r.PostForm.Get("serial")), ":", ""), 16)
	if !okSerial || n.Sign() <= 0 || n.BitLen() > 160 {
		s.fail(w, r, "certs", http.StatusBadRequest, i18n.T("シリアルが不正", "invalid serial"))
		return
	}
	serial := fmt.Sprintf("%x", n)
	if !requireConfirm(r) {
		s.fail(w, r, "certs", http.StatusBadRequest, i18n.T("確認のチェックを入れてから失効させる", "tick the confirmation box before revoking"))
		return
	}
	switch err := s.revoke(serial, reason); {
	case errors.Is(err, store.ErrNotFound):
		s.fail(w, r, "certs", http.StatusNotFound, fmt.Sprintf(i18n.T("証明書 %s が見つからない", "certificate %s not found"), serial))
		return
	case errors.Is(err, store.ErrAlreadyRevoked):
		s.fail(w, r, "certs", http.StatusConflict, fmt.Sprintf(i18n.T("証明書 %s はすでに失効している", "certificate %s is already revoked"), serial))
		return
	case err != nil:
		s.log.Error(i18n.T("管理画面: 証明書を失効できない", "admin UI: cannot revoke a certificate"), "category", "audit", "admin", admin, "serial", serial, "err", err)
		s.fail(w, r, "certs", http.StatusInternalServerError, i18n.T("証明書を失効できない", "cannot revoke the certificate"))
		return
	}
	s.log.Warn(i18n.T("管理画面: 証明書を失効", "admin UI: revoked a certificate"), "category", "audit", "admin", admin, "serial", serial, "reason", reason)
	redirectDone(w, r, "/certs", "cert-revoked", serial)
}

// fail は操作の失敗を、その画面に重ねて表示する（状態は変わっていないので redirect しない）。
func (s *Server) fail(w http.ResponseWriter, r *http.Request, page string, status int, msg string) {
	load := map[string]func(*http.Request) (any, error){"eab": s.eabData, "certs": s.certsData, "federation": s.federationData}[page]
	data, err := load(r)
	if err != nil {
		s.log.Error(i18n.T("管理画面: データを読めない", "admin UI: cannot read data"), "page", page, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, status, page, data, msg, true)
}

// 操作の成功は、決まった種類と引数（kid・シリアル）だけを URL に載せて画面に戻す（POST の後の再読み込みで
// 操作が繰り返されないように）。文言はサーバ側で組み立てるので、URL に任意の文言を仕込んで表示させることはできない。
var (
	kidRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	serialRe = regexp.MustCompile(`^[0-9a-f]{1,40}$`)
	fedIDRe  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)
	doneMsgs = map[string]struct {
		arg  *regexp.Regexp
		text func() string // 表示のたびに、そのときの言語で文言を作る
	}{
		"eab-revoked": {kidRe, func() string {
			return i18n.T("EAB 鍵 %s を取り消した。この鍵で登録したサーバは、以後新しい証明書を取得できない（発行済みの証明書は期限まで有効。すぐに止めるには失効させる）", "revoked EAB key %s. Servers registered with this key can no longer obtain new certificates (certificates already issued stay valid until they expire; revoke them to stop them immediately)")
		}},
		"cert-revoked": {serialRe, func() string {
			return i18n.T("証明書 %s を失効させた。CRL に反映される", "revoked certificate %s; it appears in the CRL")
		}},
		"fed-imported": {fedIDRe, func() string {
			return i18n.T("連携先 %s を取り込んだ（承認待ち）。指紋の全体を、前もって知っている相手の連絡先と別の経路で照合してから、承認を申請する", "imported partner %s (pending approval). Compare the full fingerprint with a contact you already knew, over a separate channel, before requesting approval")
		}},
		"fed-requested": {fedIDRe, func() string {
			return i18n.T("連携先 %s の承認を申請した。別の管理者が承認すると、トラストバンドルに入る", "requested approval of partner %s. It enters the trust bundle once another administrator approves it")
		}},
		"fed-approved": {fedIDRe, func() string {
			return i18n.T("連携先 %s を承認した。各サーバには次のトラストバンドルの取得（既定 1 分以内）で届く", "approved partner %s. Servers receive it with the next trust bundle fetch (within 1 minute by default)")
		}},
		"fed-suspended": {fedIDRe, func() string {
			return i18n.T("連携先 %s を停止した。各サーバには既定 1 分以内に届く（CA と各サーバの通信が妨げられていると、最悪はバンドルの有効期限まで残る）", "suspended partner %s. Servers receive it within 1 minute by default (if traffic between the CA and the servers is blocked, trust may remain until the bundle expires in the worst case)")
		}},
		"fed-removed": {fedIDRe, func() string { return i18n.T("連携先 %s を消した", "removed partner %s") }},
		"fed-announced": {fedIDRe, func() string {
			return i18n.T("連携先 %s のルート CA の入れ替えの予告を取り込んだ（署名は、いま信頼しているルートで確かめた）。次のルートを承認すると、新旧の両方を信頼する", "imported the root CA rotation announcement for partner %s (signature verified with the currently trusted root). Approve the next root to trust both the old and new roots")
		}},
		"fed-approve-next": {fedIDRe, func() string {
			return i18n.T("連携先 %s の次のルートを承認した。新旧の両方のルートを同じ範囲で信頼する", "approved the next root of partner %s; both the old and new roots are trusted with the same scope")
		}},
		"fed-retire-root": {fedIDRe, func() string {
			return i18n.T("連携先 %s の古いルートを外し、次のルートを今のルートにした", "removed the old root of partner %s and made the next root the current one")
		}},
		"fed-cancel-next": {fedIDRe, func() string {
			return i18n.T("連携先 %s の次のルートを取り消した", "cancelled the next root of partner %s")
		}},
	}
)

func redirectDone(w http.ResponseWriter, r *http.Request, path, kind, arg string) {
	q := url.Values{"done": {kind}, "arg": {arg}}
	http.Redirect(w, r, path+"?"+q.Encode(), http.StatusSeeOther)
}

// flashMessage は redirectDone で付けた結果を文言にする。知らない種類や書式に合わない引数は表示しない。
func flashMessage(r *http.Request) string {
	q := r.URL.Query()
	m, ok := doneMsgs[q.Get("done")]
	if !ok || !m.arg.MatchString(q.Get("arg")) {
		return ""
	}
	return fmt.Sprintf(m.text(), q.Get("arg"))
}

// checkWritable は dir にファイルを作れるかを確かめる（EAB 鍵ファイルの書き換えとロックファイルに必要）。
func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".mtls-ca-write-check-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}
