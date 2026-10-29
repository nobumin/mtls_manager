package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
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

// handleEABCreate は EAB 鍵を発行し、その HMAC 鍵を一度だけ表示する。
func (s *Server) handleEABCreate(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.checkPost(w, r, "eab_create")
	if !ok {
		return
	}
	patterns := strings.FieldsFunc(r.PostForm.Get("names"), func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\r' || c == '\t' })
	note := strings.TrimSpace(r.PostForm.Get("note"))
	if utf8.RuneCountInString(note) > 200 {
		redirect(w, r, "/eab", "error", "メモは 200 文字まで")
		return
	}
	var created eab.Key
	err := eab.Update(s.cfg.EABFile, func(f *eab.File) error {
		var err error
		created, err = f.Add(patterns, note)
		return err
	})
	if err != nil {
		s.log.Warn("管理画面: EAB 鍵を発行できない", "category", "audit", "admin", admin, "err", err)
		redirect(w, r, "/eab", "error", "EAB 鍵を発行できない: "+err.Error())
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
	if !requireConfirm(r) {
		redirect(w, r, "/eab", "error", "確認のチェックを入れてから取り消す")
		return
	}
	var removed bool
	err := eab.Update(s.cfg.EABFile, func(f *eab.File) error {
		removed = f.Remove(kid)
		if !removed {
			return errors.New("見つからない")
		}
		return nil
	})
	if err != nil {
		s.log.Warn("管理画面: EAB 鍵を取り消せない", "category", "audit", "admin", admin, "eab_kid", kid, "err", err)
		redirect(w, r, "/eab", "error", fmt.Sprintf("EAB 鍵 %s を取り消せない: %v", kid, err))
		return
	}
	s.log.Warn("管理画面: EAB 鍵を取り消し", "category", "audit", "admin", admin, "eab_kid", kid)
	redirect(w, r, "/eab", "ok", fmt.Sprintf("EAB 鍵 %s を取り消した。この鍵で登録したサーバは、以後新しい証明書を取得できない（発行済みの証明書は期限まで有効。すぐに止めるには失効させる）", kid))
}

// handleCertRevoke は証明書を失効させる。
func (s *Server) handleCertRevoke(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.checkPost(w, r, "cert_revoke")
	if !ok {
		return
	}
	raw := r.PostForm.Get("serial")
	reason, err := strconv.Atoi(r.PostForm.Get("reason"))
	if err != nil || !store.ValidRevocationReason(reason) {
		redirect(w, r, "/certs", "error", "失効理由が不正")
		return
	}
	n, okSerial := new(big.Int).SetString(strings.ReplaceAll(strings.ToLower(raw), ":", ""), 16)
	if !okSerial {
		redirect(w, r, "/certs", "error", "シリアルが不正")
		return
	}
	serial := fmt.Sprintf("%x", n)
	if !requireConfirm(r) {
		redirect(w, r, "/certs", "error", "確認のチェックを入れてから失効させる")
		return
	}
	switch err := s.revoke(serial, reason); {
	case errors.Is(err, store.ErrNotFound):
		redirect(w, r, "/certs", "error", "証明書 "+serial+" が見つからない")
		return
	case errors.Is(err, store.ErrAlreadyRevoked):
		redirect(w, r, "/certs", "error", "証明書 "+serial+" はすでに失効している")
		return
	case err != nil:
		s.log.Error("管理画面: 証明書を失効できない", "category", "audit", "admin", admin, "serial", serial, "err", err)
		redirect(w, r, "/certs", "error", "証明書を失効できない")
		return
	}
	s.log.Warn("管理画面: 証明書を失効", "category", "audit", "admin", admin, "serial", serial, "reason", reason)
	redirect(w, r, "/certs", "ok", "証明書 "+serial+" を失効させた。CRL に反映される")
}

// redirect は操作の結果を付けて画面に戻す（POST の後の再読み込みで操作が繰り返されないように）。
func redirect(w http.ResponseWriter, r *http.Request, path, kind, msg string) {
	q := url.Values{kind: {msg}}
	http.Redirect(w, r, path+"?"+q.Encode(), http.StatusSeeOther)
}

// flashMessage は redirect で付けた結果を取り出す。表示はテンプレートでエスケープされる。
func flashMessage(r *http.Request) (string, bool) {
	q := r.URL.Query()
	if m := q.Get("error"); m != "" {
		return truncateRunes(m, 500), true
	}
	return truncateRunes(q.Get("ok"), 500), false
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
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
