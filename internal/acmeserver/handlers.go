package acmeserver

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/eab"
	"github.com/nobumin/mtls_manager/internal/names"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/store"
)

type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type accountJSON struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders"`
}

type orderJSON struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires"`
	Identifiers    []identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	Error          *problem     `json:"error,omitempty"`
}

type challengeJSON struct {
	Type      string   `json:"type"`
	URL       string   `json:"url"`
	Status    string   `json:"status"`
	Token     string   `json:"token"`
	Validated string   `json:"validated,omitempty"`
	Error     *problem `json:"error,omitempty"`
}

type authzJSON struct {
	Identifier identifier      `json:"identifier"`
	Status     string          `json:"status"`
	Expires    string          `json:"expires"`
	Challenges []challengeJSON `json:"challenges"`
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// ---- アカウント ----

func (s *Server) accountView(a *store.Account) accountJSON {
	return accountJSON{Status: a.Status, Contact: a.Contact, Orders: s.url(pathAccount + a.ID + "/orders")}
}

func (s *Server) handleNewAccount(_ *http.Request, req *request) (*reply, *problem) {
	var p struct {
		Contact                []string        `json:"contact"`
		OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
		ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
	}
	if err := json.Unmarshal(req.payload, &p); err != nil {
		return nil, malformed("newAccount の内容を解釈できない")
	}
	tp, err := thumbprint(req.jwk)
	if err != nil {
		return nil, newProblem(http.StatusBadRequest, "badPublicKey", "アカウント鍵を扱えない")
	}
	existing, err := s.db.AccountByThumbprint(tp)
	switch {
	case err == nil:
		// 同じ鍵のアカウントがあれば、EAB を問わずそれを返す（RFC 8555 §7.3.1）。
		return &reply{status: http.StatusOK, body: s.accountView(existing), location: s.url(pathAccount + existing.ID)}, nil
	case !errors.Is(err, store.ErrNotFound):
		return nil, serverInternal("アカウントを確認できない")
	case p.OnlyReturnExisting:
		return nil, newProblem(http.StatusBadRequest, "accountDoesNotExist", "アカウントが存在しない")
	}

	k, prob := s.verifyEAB(p.ExternalAccountBinding, req.jwk)
	if prob != nil {
		return nil, prob
	}
	jwkJSON, err := req.jwk.MarshalJSON()
	if err != nil {
		return nil, serverInternal("アカウント鍵を保存できない")
	}
	acct, created, err := s.db.CreateAccount(&store.Account{
		ID: randomID(16), Status: store.StatusValid, JWK: jwkJSON, Thumbprint: tp,
		Contact: p.Contact, EABKeyID: k.KID, CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		return nil, serverInternal("アカウントを保存できない")
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		s.log.Info("アカウントを作成", "account", acct.ID, "eab_kid", k.KID, "eab_note", k.Note)
	}
	return &reply{status: status, body: s.accountView(acct), location: s.url(pathAccount + acct.ID)}, nil
}

func (s *Server) handleAccount(r *http.Request, req *request) (*reply, *problem) {
	if r.PathValue("id") != req.account.ID {
		return nil, unauthorized("他のアカウントは操作できない")
	}
	acct := req.account
	if !req.postAsGet {
		var p struct {
			Status  string   `json:"status"`
			Contact []string `json:"contact"`
		}
		if err := json.Unmarshal(req.payload, &p); err != nil {
			return nil, malformed("アカウント更新の内容を解釈できない")
		}
		if p.Status != "" && p.Status != store.StatusDeactivated {
			return nil, malformed("status は deactivated のみ指定できる")
		}
		updated, err := s.db.UpdateAccount(acct.ID, func(a *store.Account) error {
			if p.Status == store.StatusDeactivated {
				a.Status = store.StatusDeactivated
			}
			if p.Contact != nil {
				a.Contact = p.Contact
			}
			return nil
		})
		if err != nil {
			return nil, serverInternal("アカウントを更新できない")
		}
		if p.Status == store.StatusDeactivated {
			s.log.Info("アカウントを無効化", "account", acct.ID)
		}
		acct = updated
	}
	return &reply{status: http.StatusOK, body: s.accountView(acct), location: s.url(pathAccount + acct.ID)}, nil
}

func (s *Server) handleAccountOrders(r *http.Request, req *request) (*reply, *problem) {
	if r.PathValue("id") != req.account.ID {
		return nil, unauthorized("他のアカウントは操作できない")
	}
	ids, err := s.db.OrdersByAccount(req.account.ID)
	if err != nil {
		return nil, serverInternal("注文を読めない")
	}
	urls := make([]string, 0, len(ids))
	for _, id := range ids {
		urls = append(urls, s.url(pathOrder+id))
	}
	return &reply{status: http.StatusOK, body: map[string][]string{"orders": urls}}, nil
}

// eabFor はアカウントに結び付いた EAB 鍵を返す。鍵ファイルから削除されていれば拒否する（ホストの失効）。
func (s *Server) eabFor(acct *store.Account) (eab.Key, *problem) {
	k, ok, err := s.eab.Lookup(acct.EABKeyID)
	if err != nil {
		s.log.Error("EAB 鍵ファイルを読めない", "err", err)
		return eab.Key{}, serverInternal("EAB 鍵を確認できない")
	}
	if !ok {
		return eab.Key{}, unauthorized("このアカウントの EAB 鍵は取り消されている")
	}
	return k, nil
}

// checkNames は名前が CA の方針・中間 CA の名前制約・EAB 鍵の許可のすべてを満たすかを確かめる。
func (s *Server) checkNames(k eab.Key, list []string) *problem {
	for _, n := range list {
		if !names.WithinAnyDomain(s.cfg.Policy.AllowedDomains, n) || !s.issuer.Permits(n) {
			return newProblem(http.StatusBadRequest, "rejectedIdentifier", "%q はこの CA で発行できるドメインの範囲外", n)
		}
		if !k.Permits(n) {
			return newProblem(http.StatusBadRequest, "rejectedIdentifier", "%q はこのアカウント（EAB 鍵）には許可されていない", n)
		}
		// 管理画面に入れる名前は、その名前をワイルドカードを使わずに許可した EAB 鍵でだけ発行する。
		// サーバ用のワイルドカードの鍵（例: *.internal.example.com）で管理者の証明書を取られないようにするため。
		if names.MatchAny(s.cfg.Admin.AllowedClients, n) && !k.PermitsExactly(n) {
			s.log.Warn("管理者の名前の注文を拒否（EAB 鍵が完全一致で許可していない）", "category", "audit", "name", n, "eab_kid", k.KID)
			return newProblem(http.StatusBadRequest, "rejectedIdentifier", "%q は管理者の名前（admin.allowed_clients）なので、その名前をワイルドカードを使わずに許可した EAB 鍵でだけ発行できる", n)
		}
	}
	return nil
}

// ---- 注文 ----

func (s *Server) handleNewOrder(_ *http.Request, req *request) (*reply, *problem) {
	var p struct {
		Identifiers []identifier `json:"identifiers"`
	}
	if err := json.Unmarshal(req.payload, &p); err != nil {
		return nil, malformed("newOrder の内容を解釈できない")
	}
	if len(p.Identifiers) == 0 {
		return nil, malformed("identifiers が空")
	}
	if len(p.Identifiers) > s.cfg.Policy.MaxNamesPerOrder {
		return nil, newProblem(http.StatusBadRequest, "rejectedIdentifier", "名前は %d 個まで", s.cfg.Policy.MaxNamesPerOrder)
	}
	list := make([]string, 0, len(p.Identifiers))
	for _, id := range p.Identifiers {
		if id.Type != "dns" {
			return nil, newProblem(http.StatusBadRequest, "unsupportedIdentifier", "識別子は dns のみ（%q）", id.Type)
		}
		n := names.Normalize(id.Value)
		if err := names.ValidateHostname(n); err != nil {
			return nil, newProblem(http.StatusBadRequest, "rejectedIdentifier", "%v", err)
		}
		list = append(list, n)
	}
	slices.Sort(list)
	list = slices.Compact(list)

	k, prob := s.eabFor(req.account)
	if prob != nil {
		return nil, prob
	}
	if prob := s.checkNames(k, list); prob != nil {
		return nil, prob
	}

	now := time.Now().UTC()
	expires := now.Add(orderLifetime)
	o := &store.Order{ID: randomID(16), AccountID: req.account.ID, Status: store.StatusPending, Expires: expires, Names: list, CreatedAt: now}
	authzs := make([]*store.Authz, 0, len(list))
	for _, n := range list {
		a := &store.Authz{ID: randomID(16), AccountID: req.account.ID, OrderID: o.ID, Name: n, Status: store.StatusPending, Expires: expires}
		for _, t := range s.cfg.Challenge.Types {
			a.Challenges = append(a.Challenges, store.Challenge{Type: t, Token: randomID(32), Status: store.StatusPending})
		}
		authzs = append(authzs, a)
		o.AuthzIDs = append(o.AuthzIDs, a.ID)
	}
	if err := s.db.CreateOrder(o, authzs); err != nil {
		return nil, serverInternal("注文を保存できない")
	}
	s.log.Info("注文を受付", "order", o.ID, "account", req.account.ID, "names", list)
	view, prob := s.orderView(o)
	if prob != nil {
		return nil, prob
	}
	return &reply{status: http.StatusCreated, body: view, location: s.url(pathOrder + o.ID)}, nil
}

// orderStatus は保存された状態と認可の状態から、注文の現在の状態を導く。
func (s *Server) orderStatus(o *store.Order, now time.Time) (string, *problem, error) {
	if o.Status != store.StatusPending {
		return o.Status, fromStored(o.Error), nil
	}
	if now.After(o.Expires) {
		return store.StatusInvalid, newProblem(0, "malformed", "注文の期限が切れた"), nil
	}
	ready := true
	for _, id := range o.AuthzIDs {
		a, err := s.db.Authz(id)
		if err != nil {
			return "", nil, err
		}
		switch authzStatus(a, now) {
		case store.StatusInvalid:
			return store.StatusInvalid, newProblem(0, "unauthorized", "%s の所有確認に失敗した", a.Name), nil
		case store.StatusValid:
		default:
			ready = false
		}
	}
	if ready {
		return store.StatusReady, nil, nil
	}
	return store.StatusPending, nil, nil
}

func authzStatus(a *store.Authz, now time.Time) string {
	if a.Status == store.StatusPending && now.After(a.Expires) {
		return store.StatusInvalid
	}
	return a.Status
}

func (s *Server) orderView(o *store.Order) (orderJSON, *problem) {
	status, oerr, err := s.orderStatus(o, time.Now())
	if err != nil {
		return orderJSON{}, serverInternal("注文の状態を読めない")
	}
	v := orderJSON{Status: status, Expires: rfc3339(o.Expires), Finalize: s.url(pathOrder + o.ID + "/finalize"), Error: oerr}
	for _, n := range o.Names {
		v.Identifiers = append(v.Identifiers, identifier{Type: "dns", Value: n})
	}
	for _, id := range o.AuthzIDs {
		v.Authorizations = append(v.Authorizations, s.url(pathAuthz+id))
	}
	if o.CertSerial != "" {
		v.Certificate = s.url(pathCert + o.CertSerial)
	}
	return v, nil
}

func (s *Server) ownedOrder(id string, acct *store.Account) (*store.Order, *problem) {
	o, err := s.db.Order(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("注文")
	}
	if err != nil {
		return nil, serverInternal("注文を読めない")
	}
	if o.AccountID != acct.ID {
		return nil, unauthorized("他のアカウントの注文")
	}
	return o, nil
}

func (s *Server) handleOrder(r *http.Request, req *request) (*reply, *problem) {
	if !req.postAsGet {
		return nil, malformed("注文の取得は POST-as-GET で行う")
	}
	o, prob := s.ownedOrder(r.PathValue("id"), req.account)
	if prob != nil {
		return nil, prob
	}
	view, prob := s.orderView(o)
	if prob != nil {
		return nil, prob
	}
	return &reply{status: http.StatusOK, body: view, location: s.url(pathOrder + o.ID)}, nil
}

// ---- 認可・チャレンジ ----

func (s *Server) ownedAuthz(id string, acct *store.Account) (*store.Authz, *problem) {
	a, err := s.db.Authz(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("認可")
	}
	if err != nil {
		return nil, serverInternal("認可を読めない")
	}
	if a.AccountID != acct.ID {
		return nil, unauthorized("他のアカウントの認可")
	}
	return a, nil
}

func (s *Server) challengeView(a *store.Authz, c store.Challenge) challengeJSON {
	v := challengeJSON{Type: c.Type, URL: s.url(pathChall + a.ID + "/" + c.Type), Status: c.Status, Token: c.Token, Error: fromStored(c.Error)}
	if c.Validated != nil {
		v.Validated = rfc3339(*c.Validated)
	}
	return v
}

func (s *Server) authzView(a *store.Authz) authzJSON {
	v := authzJSON{Identifier: identifier{Type: "dns", Value: a.Name}, Status: authzStatus(a, time.Now()), Expires: rfc3339(a.Expires)}
	for _, c := range a.Challenges {
		v.Challenges = append(v.Challenges, s.challengeView(a, c))
	}
	return v
}

func (s *Server) handleAuthz(r *http.Request, req *request) (*reply, *problem) {
	if !req.postAsGet {
		return nil, malformed("認可の取得は POST-as-GET で行う")
	}
	a, prob := s.ownedAuthz(r.PathValue("id"), req.account)
	if prob != nil {
		return nil, prob
	}
	v := s.authzView(a)
	return &reply{status: http.StatusOK, body: v, retryAfter: v.Status == store.StatusPending}, nil
}

var errAlreadyStarted = errors.New("already started")

func (s *Server) handleChallenge(r *http.Request, req *request) (*reply, *problem) {
	a, prob := s.ownedAuthz(r.PathValue("authz"), req.account)
	if prob != nil {
		return nil, prob
	}
	typ := r.PathValue("type")
	idx := slices.IndexFunc(a.Challenges, func(c store.Challenge) bool { return c.Type == typ })
	if idx < 0 {
		return nil, notFound("チャレンジ")
	}
	up := s.url(pathAuthz + a.ID)

	if !req.postAsGet {
		// 応答の準備ができたという通知（payload は {}）。確認を非同期で始める。
		var p map[string]any
		if err := json.Unmarshal(req.payload, &p); err != nil {
			return nil, malformed("チャレンジの内容を解釈できない")
		}
		updated, err := s.db.UpdateAuthz(a.ID, func(x *store.Authz) error {
			if authzStatus(x, time.Now()) != store.StatusPending || x.Challenges[idx].Status != store.StatusPending {
				return errAlreadyStarted
			}
			// 同じ認可で別のチャレンジを並行させない。
			for _, c := range x.Challenges {
				if c.Status == store.StatusProcessing {
					return errAlreadyStarted
				}
			}
			x.Challenges[idx].Status = store.StatusProcessing
			return nil
		})
		switch {
		case err == nil:
			a = updated
			s.startValidation(a.ID, idx, req.account.Thumbprint)
		case errors.Is(err, errAlreadyStarted):
			// すでに確認中・確定済み。現在の状態を返す（クライアントの再送に冪等に応じる）。
		default:
			return nil, serverInternal("チャレンジを更新できない")
		}
	}
	c := a.Challenges[idx]
	return &reply{status: http.StatusOK, body: s.challengeView(a, c), up: up, retryAfter: c.Status == store.StatusProcessing}, nil
}

func (s *Server) startValidation(authzID string, idx int, accountThumbprint string) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		a, err := s.db.Authz(authzID)
		if err != nil {
			s.log.Error("認可を読めない", "authz", authzID, "err", err)
			return
		}
		c := a.Challenges[idx]
		keyAuth := c.Token + "." + accountThumbprint
		var prob *problem
		for attempt := 1; attempt <= s.cfg.Challenge.Attempts; attempt++ {
			switch c.Type {
			case config.ChallengeHTTP01:
				prob = s.validator.validateHTTP01(s.ctx, a.Name, c.Token, keyAuth)
			case config.ChallengeTLSALPN01:
				prob = s.validator.validateTLSALPN01(s.ctx, a.Name, keyAuth)
			default:
				prob = serverInternal("未対応のチャレンジ %q", c.Type)
			}
			if prob == nil || attempt == s.cfg.Challenge.Attempts {
				break
			}
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
		// CA の停止で確認が取り消された場合は、結果を保存しない（取り消しを恒久的な失敗として記録しない）。
		// processing のまま残ったチャレンジは、次の起動時に pending へ戻す（ResetProcessingChallenges）。
		if s.ctx.Err() != nil {
			return
		}
		now := time.Now().UTC()
		_, err = s.db.UpdateAuthz(authzID, func(x *store.Authz) error {
			ch := &x.Challenges[idx]
			if prob == nil {
				ch.Status, ch.Validated, x.Status = store.StatusValid, &now, store.StatusValid
			} else {
				ch.Status, ch.Error, x.Status = store.StatusInvalid, prob.stored(), store.StatusInvalid
			}
			return nil
		})
		if err != nil {
			s.log.Error("確認結果を保存できない", "authz", authzID, "err", err)
			return
		}
		if prob == nil {
			s.log.Info("所有確認に成功", "name", a.Name, "type", c.Type, "order", a.OrderID)
		} else {
			s.log.Warn("所有確認に失敗", "name", a.Name, "type", c.Type, "order", a.OrderID, "detail", prob.Detail)
		}
	}()
}

// ---- 発行 ----

var errNotReady = errors.New("not ready")

func (s *Server) handleFinalize(r *http.Request, req *request) (*reply, *problem) {
	o, prob := s.ownedOrder(r.PathValue("id"), req.account)
	if prob != nil {
		return nil, prob
	}
	status, _, err := s.orderStatus(o, time.Now())
	if err != nil {
		return nil, serverInternal("注文の状態を読めない")
	}
	if status != store.StatusReady {
		return nil, newProblem(http.StatusForbidden, "orderNotReady", "注文の状態が %s（ready ではない）", status)
	}
	var p struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(req.payload, &p); err != nil {
		return nil, malformed("finalize の内容を解釈できない")
	}
	der, err := base64.RawURLEncoding.DecodeString(p.CSR)
	if err != nil {
		return nil, newProblem(http.StatusBadRequest, "badCSR", "csr を base64url として解釈できない")
	}
	csr, prob := parseCSR(der, o.Names)
	if prob != nil {
		return nil, prob
	}
	// 注文から発行までの間に EAB 鍵が取り消されていないか、もう一度確かめる。
	k, prob := s.eabFor(req.account)
	if prob != nil {
		return nil, prob
	}
	if prob := s.checkNames(k, o.Names); prob != nil {
		return nil, prob
	}

	// 二重発行を防ぐため、pending → processing を 1 トランザクションで行う。
	if _, err := s.db.UpdateOrder(o.ID, func(x *store.Order) error {
		if x.Status != store.StatusPending {
			return errNotReady
		}
		x.Status = store.StatusProcessing
		return nil
	}); err != nil {
		if errors.Is(err, errNotReady) {
			return nil, newProblem(http.StatusForbidden, "orderNotReady", "注文はすでに処理されている")
		}
		return nil, serverInternal("注文を更新できない")
	}

	fail := func(p *problem) (*reply, *problem) {
		_, _ = s.db.UpdateOrder(o.ID, func(x *store.Order) error {
			x.Status, x.Error = store.StatusInvalid, p.stored()
			return nil
		})
		return nil, p
	}

	// 署名する前にシリアルを記録する。署名後に記録できなくても（プロセスが落ちても）、
	// 発行した証明書は必ず一覧・失効・CRL の対象になる。
	validity := s.cfg.Cert.Validity.D()
	serialNum, err := pki.RandomSerial()
	if err != nil {
		return fail(serverInternal("シリアルを作れない"))
	}
	serial := fmt.Sprintf("%x", serialNum)
	now := time.Now()
	if err := s.db.ReserveCert(&store.Cert{
		Serial: serial, AccountID: req.account.ID, OrderID: o.ID, Names: o.Names,
		NotBefore: now, NotAfter: s.issuer.LeafNotAfter(now, validity),
	}); err != nil {
		s.log.Error("発行の記録を作れない", "order", o.ID, "err", err)
		return fail(serverInternal("発行の記録を作れない"))
	}
	leaf, err := s.issuer.IssueLeafWithSerial(serialNum, csr.PublicKey, o.Names, validity)
	if err != nil {
		_ = s.db.DeleteReservedCert(serial)
		if errors.Is(err, pki.ErrIssuerExpiring) {
			s.log.Error("中間 CA の有効期限が近いため発行を拒否した。中間 CA を更新すること", "order", o.ID, "intermediate_not_after", s.issuer.Cert.NotAfter)
			return fail(serverInternal("中間 CA の有効期限が近いため発行できない"))
		}
		s.log.Error("証明書を発行できない", "order", o.ID, "err", err)
		return fail(serverInternal("証明書を発行できない"))
	}
	if leaf.NotAfter.Before(now.Add(validity - time.Minute)) {
		s.log.Warn("中間 CA の有効期限に合わせて、証明書の有効期間を短くした。中間 CA を更新すること",
			"serial", serial, "not_after", leaf.NotAfter, "intermediate_not_after", s.issuer.Cert.NotAfter)
	}
	if err := s.db.FinalizeOrder(o.ID, &store.Cert{
		Serial: serial, AccountID: req.account.ID, OrderID: o.ID, Names: o.Names,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, IssuedAt: time.Now().UTC(), ChainPEM: pki.EncodeCertsPEM(leaf, s.issuer.Cert),
	}); err != nil {
		// 予約の記録は残っているので、このシリアルは失効できる。
		s.log.Error("発行した証明書を記録できない（予約の記録は残っている）", "order", o.ID, "serial", serial, "err", err)
		return fail(serverInternal("発行履歴を保存できない"))
	}
	s.log.Info("証明書を発行", "serial", serial, "names", o.Names, "not_after", leaf.NotAfter, "account", req.account.ID, "eab_kid", k.KID)

	o, err = s.db.Order(o.ID)
	if err != nil {
		return nil, serverInternal("注文を読めない")
	}
	view, prob := s.orderView(o)
	if prob != nil {
		return nil, prob
	}
	return &reply{status: http.StatusOK, body: view, location: s.url(pathOrder + o.ID)}, nil
}

// parseCSR は CSR を検証し、名前が注文と完全に一致することを確かめる。
func parseCSR(der []byte, want []string) (*x509.CertificateRequest, *problem) {
	bad := func(format string, args ...any) (*x509.CertificateRequest, *problem) {
		return nil, newProblem(http.StatusBadRequest, "badCSR", format, args...)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return bad("CSR を解釈できない: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return bad("CSR の署名が不正")
	}
	if err := pki.CheckPublicKey(csr.PublicKey); err != nil {
		return nil, newProblem(http.StatusBadRequest, "badPublicKey", "%v", err)
	}
	if len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) != 0 {
		return bad("CSR に DNS 名以外の名前は含められない")
	}
	got := make([]string, 0, len(csr.DNSNames)+1)
	for _, n := range csr.DNSNames {
		got = append(got, names.Normalize(n))
	}
	if cn := csr.Subject.CommonName; cn != "" {
		got = append(got, names.Normalize(cn))
	}
	slices.Sort(got)
	got = slices.Compact(got)
	if !slices.Equal(got, want) {
		return bad("CSR の名前 %v が注文 %v と一致しない", got, want)
	}
	return csr, nil
}

func (s *Server) handleCert(r *http.Request, req *request) (*reply, *problem) {
	if !req.postAsGet {
		return nil, malformed("証明書の取得は POST-as-GET で行う")
	}
	c, err := s.db.Cert(r.PathValue("serial"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("証明書")
	}
	if err != nil {
		return nil, serverInternal("証明書を読めない")
	}
	if c.AccountID != req.account.ID {
		return nil, unauthorized("他のアカウントの証明書")
	}
	if c.Pending {
		return nil, notFound("証明書")
	}
	return &reply{status: http.StatusOK, raw: c.ChainPEM, contentType: "application/pem-certificate-chain"}, nil
}

// ---- 失効 ----

func (s *Server) handleRevoke(_ *http.Request, req *request) (*reply, *problem) {
	var p struct {
		Certificate string `json:"certificate"`
		Reason      *int   `json:"reason"`
	}
	if err := json.Unmarshal(req.payload, &p); err != nil {
		return nil, malformed("revokeCert の内容を解釈できない")
	}
	reason := 0
	if p.Reason != nil {
		reason = *p.Reason
	}
	if !store.ValidRevocationReason(reason) {
		return nil, newProblem(http.StatusBadRequest, "badRevocationReason", "失効理由 %d は受け付けない（%v）", reason, store.RevocationReasons)
	}
	der, err := base64.RawURLEncoding.DecodeString(p.Certificate)
	if err != nil {
		return nil, malformed("certificate を base64url として解釈できない")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, malformed("certificate を解釈できない")
	}
	serial := fmt.Sprintf("%x", cert.SerialNumber)
	err = s.db.RevokeCert(serial, reason, func(c *store.Cert) error {
		if c.AccountID != req.account.ID {
			return errUnauthorized
		}
		return nil
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, notFound("証明書")
	case errors.Is(err, errUnauthorized):
		return nil, unauthorized("他のアカウントの証明書は失効できない")
	case errors.Is(err, store.ErrAlreadyRevoked):
		return nil, newProblem(http.StatusBadRequest, "alreadyRevoked", "すでに失効している")
	case err != nil:
		return nil, serverInternal("失効を保存できない")
	}
	s.crlMu.Lock()
	s.crlDirty = true
	s.crlMu.Unlock()
	s.log.Info("証明書を失効", "serial", serial, "reason", reason, "account", req.account.ID)
	return &reply{status: http.StatusOK, raw: []byte{}, contentType: "text/plain"}, nil
}

var errUnauthorized = errors.New("unauthorized")

// RevokeByAdmin は管理画面から証明書を失効させる（アカウントを問わない）。失効は次の CRL に反映される。
func (s *Server) RevokeByAdmin(serial string, reason int) error {
	if err := s.db.RevokeCert(serial, reason, nil); err != nil {
		return err
	}
	s.crlMu.Lock()
	s.crlDirty = true
	s.crlMu.Unlock()
	return nil
}
