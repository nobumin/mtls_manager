package acmeserver

import (
	"crypto"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/nobumin/mtls_manager/internal/eab"
	"github.com/nobumin/mtls_manager/internal/store"
)

// アカウント鍵の署名に使える方式。HMAC と "none" は受け付けない。
var accountAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.RS256, jose.EdDSA}

// EAB の内側の JWS に使える方式。
var eabAlgs = []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512}

const maxBodyBytes = 64 << 10

// request は検証済みの ACME リクエスト。
type request struct {
	payload   []byte
	postAsGet bool
	jwk       *jose.JSONWebKey // newAccount のとき
	account   *store.Account   // kid のとき
}

// verify はリクエストの JWS を検証する（RFC 8555 §6.2〜6.5）。
// wantJWK が true なら jwk ヘッダ（newAccount）、false なら kid ヘッダ（既存アカウント）を要求する。
func (s *Server) verify(r *http.Request, wantJWK bool) (*request, *problem) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/jose+json" {
		return nil, newProblem(http.StatusUnsupportedMediaType, "malformed", "Content-Type は application/jose+json")
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err != nil {
		return nil, malformed("リクエストを読めない: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		return nil, malformed("JWS は Flattened JSON 形式にする")
	}
	obj, err := jose.ParseSigned(string(body), accountAlgs)
	if err != nil {
		return nil, newProblem(http.StatusBadRequest, "badSignatureAlgorithm", "JWS を解釈できない: %v", err)
	}
	if len(obj.Signatures) != 1 {
		return nil, malformed("署名は 1 つだけにする")
	}
	sig := obj.Signatures[0]
	if !emptyHeader(sig.Unprotected) {
		return nil, malformed("保護されていないヘッダは使えない")
	}
	h := sig.Protected

	if h.Nonce == "" || !s.nonces.consume(h.Nonce) {
		return nil, newProblem(http.StatusBadRequest, "badNonce", "nonce が無効")
	}
	if u, _ := h.ExtraHeaders["url"].(string); u != s.url(r.URL.Path) {
		return nil, unauthorized("url ヘッダがリクエスト先と一致しない")
	}

	req := &request{}
	var key *jose.JSONWebKey
	switch {
	case h.JSONWebKey != nil && h.KeyID != "":
		return nil, malformed("jwk と kid は同時に使えない")
	case wantJWK:
		if h.JSONWebKey == nil {
			return nil, malformed("このリクエストには jwk ヘッダが必要")
		}
		if err := checkAccountKey(h.JSONWebKey); err != nil {
			return nil, newProblem(http.StatusBadRequest, "badPublicKey", "%v", err)
		}
		key, req.jwk = h.JSONWebKey, h.JSONWebKey
	default:
		if h.KeyID == "" {
			return nil, malformed("このリクエストには kid ヘッダが必要")
		}
		id, ok := strings.CutPrefix(h.KeyID, s.url(pathAccount))
		if !ok || id == "" || strings.Contains(id, "/") {
			return nil, newProblem(http.StatusBadRequest, "accountDoesNotExist", "kid が不正")
		}
		acct, err := s.db.Account(id)
		if errors.Is(err, store.ErrNotFound) {
			return nil, newProblem(http.StatusBadRequest, "accountDoesNotExist", "アカウントが存在しない")
		}
		if err != nil {
			return nil, serverInternal("アカウントを読めない")
		}
		if acct.Status != store.StatusValid {
			return nil, unauthorized("アカウントが無効")
		}
		key = &jose.JSONWebKey{}
		if err := key.UnmarshalJSON(acct.JWK); err != nil {
			return nil, serverInternal("アカウント鍵を読めない")
		}
		req.account = acct
	}

	payload, err := obj.Verify(key)
	if err != nil {
		return nil, malformed("署名の検証に失敗した")
	}
	req.payload = payload
	req.postAsGet = len(payload) == 0
	return req, nil
}

func emptyHeader(h jose.Header) bool {
	return h.KeyID == "" && h.JSONWebKey == nil && h.Algorithm == "" && h.Nonce == "" && len(h.ExtraHeaders) == 0
}

func checkAccountKey(k *jose.JSONWebKey) error {
	if !k.Valid() || !k.IsPublic() {
		return errors.New("jwk は有効な公開鍵にする")
	}
	if rk, ok := k.Key.(*rsa.PublicKey); ok && rk.N.BitLen() < 2048 {
		return errors.New("RSA のアカウント鍵は 2048 bit 以上")
	}
	return nil
}

func thumbprint(k *jose.JSONWebKey) (string, error) {
	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// verifyEAB は newAccount の externalAccountBinding（RFC 8555 §7.3.4）を検証し、使われた EAB 鍵を返す。
func (s *Server) verifyEAB(raw json.RawMessage, accountKey *jose.JSONWebKey) (eab.Key, *problem) {
	if len(raw) == 0 || string(raw) == "null" {
		return eab.Key{}, newProblem(http.StatusUnauthorized, "externalAccountRequired", "この CA は External Account Binding が必須")
	}
	obj, err := jose.ParseSigned(string(raw), eabAlgs)
	if err != nil {
		return eab.Key{}, malformed("externalAccountBinding を解釈できない: %v", err)
	}
	if len(obj.Signatures) != 1 || !emptyHeader(obj.Signatures[0].Unprotected) {
		return eab.Key{}, malformed("externalAccountBinding の形式が不正")
	}
	h := obj.Signatures[0].Protected
	if h.Nonce != "" {
		return eab.Key{}, malformed("externalAccountBinding に nonce は含めない")
	}
	if u, _ := h.ExtraHeaders["url"].(string); u != s.url(pathNewAccount) {
		return eab.Key{}, unauthorized("externalAccountBinding の url が不正")
	}
	k, ok, err := s.eab.Lookup(h.KeyID)
	if err != nil {
		s.log.Error("EAB 鍵ファイルを読めない", "err", err)
		return eab.Key{}, serverInternal("EAB 鍵を確認できない")
	}
	if !ok {
		return eab.Key{}, unauthorized("EAB 鍵が無効")
	}
	hmacKey, err := k.HMACKey()
	if err != nil {
		return eab.Key{}, serverInternal("EAB 鍵を確認できない")
	}
	payload, err := obj.Verify(hmacKey)
	if err != nil {
		return eab.Key{}, unauthorized("EAB の署名の検証に失敗した")
	}
	var bound jose.JSONWebKey
	if err := bound.UnmarshalJSON(payload); err != nil {
		return eab.Key{}, malformed("EAB の内容が JWK ではない")
	}
	got, err1 := thumbprint(&bound)
	want, err2 := thumbprint(accountKey)
	if err1 != nil || err2 != nil || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return eab.Key{}, unauthorized("EAB がアカウント鍵と一致しない")
	}
	return k, nil
}
