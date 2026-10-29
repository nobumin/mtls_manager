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
		s.log.Warn("管理画面: 変更の操作を拒否", "category", "audit", "admin", admin, "action", action, "reason", reason, "remote", r.RemoteAddr)
		http.Error(w, reason, status)
		return admin, false
	}
	if !s.isOperator(admin) {
		return reject(http.StatusForbidden, "この管理者には変更の権限がない（admin.operators）")
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return reject(http.StatusForbidden, "他のサイトからの送信は受け付けない")
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host {
			return reject(http.StatusForbidden, "他のサイトからの送信は受け付けない")
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		return reject(http.StatusBadRequest, "フォームを解釈できない")
	}
	if !hmac.Equal([]byte(r.PostForm.Get("csrf")), []byte(s.csrfToken(admin))) {
		return reject(http.StatusForbidden, "フォームのトークンが無効（画面を開き直してやり直す）")
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
		s.fail(w, r, "eab", http.StatusBadRequest, "フォームが古い。画面を開き直してやり直す")
		return
	}
	patterns := strings.FieldsFunc(r.PostForm.Get("names"), func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\r' || c == '\t' })
	note := strings.TrimSpace(r.PostForm.Get("note"))
	if utf8.RuneCountInString(note) > 200 {
		s.fail(w, r, "eab", http.StatusBadRequest, "メモは 200 文字まで")
		return
	}
	if !s.once.use(once, time.Now()) {
		s.log.Warn("管理画面: EAB 鍵の発行の再送信を無視", "category", "audit", "admin", admin)
		s.fail(w, r, "eab", http.StatusConflict, "この発行はすでに行った（画面の再読み込みによる再送信は無視した）。発行した鍵は一覧で確かめる")
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
			return fmt.Errorf("ワイルドカード %s が管理者の名前（admin.allowed_clients）と重なる。管理者の名前はサーバと別のサブドメインにする", strings.Join(ov, ", "))
		}
		return nil
	})
	if err != nil {
		s.log.Warn("管理画面: EAB 鍵を発行できない", "category", "audit", "admin", admin, "err", err)
		s.fail(w, r, "eab", http.StatusBadRequest, "EAB 鍵を発行できない: "+err.Error())
		return
	}
	s.log.Info("管理画面: EAB 鍵を発行", "category", "audit", "admin", admin, "eab_kid", created.KID, "names", created.Names, "note", created.Note)
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
		s.fail(w, r, "eab", http.StatusBadRequest, "kid が不正")
		return
	}
	if !requireConfirm(r) {
		s.fail(w, r, "eab", http.StatusBadRequest, "確認のチェックを入れてから取り消す")
		return
	}
	err := eab.Update(s.cfg.EABFile, func(f *eab.File) error {
		if !f.Remove(kid) {
			return errors.New("見つからない")
		}
		return nil
	})
	if err != nil {
		s.log.Warn("管理画面: EAB 鍵を取り消せない", "category", "audit", "admin", admin, "eab_kid", kid, "err", err)
		s.fail(w, r, "eab", http.StatusBadRequest, fmt.Sprintf("EAB 鍵 %s を取り消せない: %v", kid, err))
		return
	}
	s.log.Warn("管理画面: EAB 鍵を取り消し", "category", "audit", "admin", admin, "eab_kid", kid)
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
		s.fail(w, r, "certs", http.StatusBadRequest, "失効理由が不正")
		return
	}
	n, okSerial := new(big.Int).SetString(strings.ReplaceAll(strings.ToLower(r.PostForm.Get("serial")), ":", ""), 16)
	if !okSerial || n.Sign() <= 0 || n.BitLen() > 160 {
		s.fail(w, r, "certs", http.StatusBadRequest, "シリアルが不正")
		return
	}
	serial := fmt.Sprintf("%x", n)
	if !requireConfirm(r) {
		s.fail(w, r, "certs", http.StatusBadRequest, "確認のチェックを入れてから失効させる")
		return
	}
	switch err := s.revoke(serial, reason); {
	case errors.Is(err, store.ErrNotFound):
		s.fail(w, r, "certs", http.StatusNotFound, "証明書 "+serial+" が見つからない")
		return
	case errors.Is(err, store.ErrAlreadyRevoked):
		s.fail(w, r, "certs", http.StatusConflict, "証明書 "+serial+" はすでに失効している")
		return
	case err != nil:
		s.log.Error("管理画面: 証明書を失効できない", "category", "audit", "admin", admin, "serial", serial, "err", err)
		s.fail(w, r, "certs", http.StatusInternalServerError, "証明書を失効できない")
		return
	}
	s.log.Warn("管理画面: 証明書を失効", "category", "audit", "admin", admin, "serial", serial, "reason", reason)
	redirectDone(w, r, "/certs", "cert-revoked", serial)
}

// fail は操作の失敗を、その画面に重ねて表示する（状態は変わっていないので redirect しない）。
func (s *Server) fail(w http.ResponseWriter, r *http.Request, page string, status int, msg string) {
	load := map[string]func(*http.Request) (any, error){"eab": s.eabData, "certs": s.certsData}[page]
	data, err := load(r)
	if err != nil {
		s.log.Error("管理画面: データを読めない", "page", page, "err", err)
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
	doneMsgs = map[string]struct {
		arg  *regexp.Regexp
		text string
	}{
		"eab-revoked":  {kidRe, "EAB 鍵 %s を取り消した。この鍵で登録したサーバは、以後新しい証明書を取得できない（発行済みの証明書は期限まで有効。すぐに止めるには失効させる）"},
		"cert-revoked": {serialRe, "証明書 %s を失効させた。CRL に反映される"},
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
	return fmt.Sprintf(m.text, q.Get("arg"))
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
