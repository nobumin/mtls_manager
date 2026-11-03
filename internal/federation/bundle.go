package federation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/nobumin/mtls_manager/internal/pki"
)

// BundleFormat はトラストバンドルの形式。
const BundleFormat = "mtls-manager-trust-bundle/v1"

// バンドルの有効期限（設計 8-1）。「CA が止まっても連携が続く期間」と「停止が届かないときの最悪の期間」を兼ねる。
const (
	DefaultBundleValidity = 48 * time.Hour
	MinBundleValidity     = time.Hour
	MaxBundleValidity     = 7 * 24 * time.Hour
)

// ErrBundleExpired はバンドルの有効期限が切れていることを表す。連携先のルートだけを外す（自分のルートは信頼し続ける）。
var ErrBundleExpired = errors.New("トラストバンドルの有効期限が切れている")

// Bundle は CA が各サーバへ配るトラストバンドル。中間 CA の鍵で署名した JWS（compact）として配る。
// 自分のルート CA と範囲は、バンドルからは取らない（OwnRoots は照合のための参照）。
type Bundle struct {
	Format string `json:"format"`
	// Epoch は mtls-ca の起動（データの初期化・復旧を含む）ごとに変わる乱数の ID。Seq は同じエポックの中で単調に増える。
	Epoch    string    `json:"epoch"`
	Seq      uint64    `json:"seq"`
	IssuedAt time.Time `json:"issued_at"`
	Expires  time.Time `json:"expires"`
	// OwnRoots は自分のルート CA の指紋の一覧（入れ替え中は新旧の 2 つ）。すべてが受け取る側の CAFile に含まれること。
	OwnRoots []string        `json:"own_roots"`
	Partners []BundlePartner `json:"partners"`
}

// BundlePartner はバンドルの中の連携先 1 件。
type BundlePartner struct {
	ID         string    `json:"id"`
	RootCert   string    `json:"root_cert"`
	RootSHA256 string    `json:"root_sha256"`
	Domains    []string  `json:"domains"`
	Expires    time.Time `json:"expires"`
	// NextRootCert はルート CA の入れ替え中の新しいルート（予告で取り込み、承認したもの）。同じ範囲で信頼する。
	NextRootCert   string `json:"next_root_cert,omitempty"`
	NextRootSHA256 string `json:"next_root_sha256,omitempty"`
}

// TrustedPartner は検証を通った連携先。
type TrustedPartner struct {
	ID   string
	Root *x509.Certificate
	// Roots は信頼するルート（Root と、入れ替え中なら次のルート）。
	Roots   []*x509.Certificate
	Domains []string
}

// Verified は検証を通ったバンドル。
type Verified struct {
	Bundle   *Bundle
	Partners []TrustedPartner
	// Dropped は、条件を満たさずに外した連携先とその理由（エラーのログに出す）。
	Dropped []string
}

// VerifyOptions はバンドルの検証の条件。
type VerifyOptions struct {
	// OwnRoots は自分のルート CA（CAFile）。バンドルの署名者（中間 CA）はこれにつながること。
	OwnRoots []*x509.Certificate
	// OwnScope は自分の範囲（自分の中間 CA の名前制約から OwnScope で得たもの）。連携先がこれと重なれば外す。
	OwnScope []string
	// SignerConstraints は署名者（中間 CA）の名前制約が一致すべき値（自分の中間 CA の名前制約）。
	// 同じルートの下の、別の範囲の中間 CA が署名したバンドルを受け入れないため。
	SignerConstraints []string
	Now               time.Time
}

// signingAlgs はバンドルの署名に使ってよいアルゴリズム。
var signingAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.ES512, jose.RS256, jose.PS256, jose.EdDSA}

func algFor(key crypto.Signer) (jose.SignatureAlgorithm, error) {
	switch k := key.Public().(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		}
	case *rsa.PublicKey:
		return jose.RS256, nil
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	}
	return "", errors.New("中間 CA の鍵の種類に対応していない")
}

// Sign はバンドルに中間 CA の鍵で署名する（x5c に中間 CA の証明書を入れる）。
func Sign(b *Bundle, inter *x509.Certificate, key crypto.Signer) (string, error) {
	alg, err := algFor(key)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	opts := (&jose.SignerOptions{}).WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(inter.Raw)})
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

// Verify はバンドルの署名と内容を確かめ、信頼してよい連携先を返す。
//   - 署名者（x5c の中間 CA）が OwnRoots につながり、名前制約が SignerConstraints と一致すること
//   - OwnRoots の指紋が空でなく、すべて o.OwnRoots に含まれること（満たさなければバンドル全体を拒否）
//   - 有効期限が切れていれば ErrBundleExpired
//   - 連携先ごとに、識別子・ルート CA・指紋・範囲（広すぎない・自分や他の連携先と重ならない）・連携の有効期限を確かめ、
//     満たさないものは外す（Dropped に理由）
//
// エポックと連番の比較（古いバンドルの再送の拒否）は、状態を持つ呼び出し側（mtls-agent）が行う。
func Verify(compact string, o VerifyOptions) (*Verified, error) {
	if len(o.OwnRoots) == 0 {
		return nil, errors.New("自分のルート CA が無い")
	}
	if len(o.SignerConstraints) == 0 {
		return nil, errors.New("自分の中間 CA の名前制約が無いので、バンドルの署名者を確かめられない")
	}
	jws, err := jose.ParseSigned(compact, signingAlgs)
	if err != nil {
		return nil, fmt.Errorf("トラストバンドルを解釈できない: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("トラストバンドルの署名は 1 つにする")
	}
	pool := x509.NewCertPool()
	for _, r := range o.OwnRoots {
		pool.AddCert(r)
	}
	chains, err := jws.Signatures[0].Protected.Certificates(x509.VerifyOptions{
		Roots: pool, CurrentTime: o.Now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("トラストバンドルの署名者を、自分のルート CA で検証できない: %w", err)
	}
	signer := chains[0][0]
	if !signer.IsCA || !slices.Equal(sortedUnique(normalizeAll(signer.PermittedDNSDomains)), sortedUnique(normalizeAll(o.SignerConstraints))) {
		return nil, errors.New("トラストバンドルの署名者が、自分の中間 CA（同じ名前制約）ではない")
	}
	payload, err := jws.Verify(signer.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("トラストバンドルの署名が正しくない: %w", err)
	}
	var b Bundle
	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, fmt.Errorf("トラストバンドルを解釈できない: %w", err)
	}
	if b.Format != BundleFormat {
		return nil, fmt.Errorf("トラストバンドルの形式 %q に対応していない", b.Format)
	}
	if b.Epoch == "" || b.Seq == 0 || b.IssuedAt.IsZero() || !b.Expires.After(b.IssuedAt) {
		return nil, errors.New("トラストバンドルのエポック・連番・発行時刻・有効期限が不正")
	}
	if len(b.OwnRoots) == 0 {
		return nil, errors.New("トラストバンドルに自分のルート CA の指紋が無い")
	}
	for _, fp := range b.OwnRoots {
		if !slices.ContainsFunc(o.OwnRoots, func(r *x509.Certificate) bool { return FingerprintEqual(fp, Fingerprint(r)) }) {
			return nil, fmt.Errorf("トラストバンドルの自分のルート CA（%s）が、CAFile のルート CA に無い", fp)
		}
	}
	v := &Verified{Bundle: &b}
	if !o.Now.Before(b.Expires) {
		return v, ErrBundleExpired
	}
	var accepted [][]string
	for _, p := range b.Partners {
		tp, reason := checkPartner(p, o, accepted)
		if reason != "" {
			v.Dropped = append(v.Dropped, fmt.Sprintf("%s: %s", p.ID, reason))
			continue
		}
		accepted = append(accepted, tp.Domains)
		v.Partners = append(v.Partners, tp)
	}
	return v, nil
}

func checkPartner(p BundlePartner, o VerifyOptions, accepted [][]string) (TrustedPartner, string) {
	if err := ValidateID(p.ID); err != nil {
		return TrustedPartner{}, err.Error()
	}
	root, err := parseRoot(p.RootCert)
	if err != nil {
		return TrustedPartner{}, err.Error()
	}
	if !FingerprintEqual(p.RootSHA256, Fingerprint(root)) {
		return TrustedPartner{}, "指紋がルート CA の証明書と一致しない"
	}
	for _, own := range o.OwnRoots {
		if own.Equal(root) {
			return TrustedPartner{}, "自分のルート CA と同じ"
		}
	}
	scope, err := NormalizeScope(p.Domains)
	if err != nil {
		return TrustedPartner{}, err.Error()
	}
	if ScopesOverlap(scope, o.OwnScope) {
		return TrustedPartner{}, fmt.Sprintf("範囲 %v が自分の範囲 %v と重なる", scope, o.OwnScope)
	}
	for _, other := range accepted {
		if ScopesOverlap(scope, other) {
			return TrustedPartner{}, fmt.Sprintf("範囲 %v が他の連携先の範囲 %v と重なる", scope, other)
		}
	}
	if !p.Expires.IsZero() && !o.Now.Before(p.Expires) {
		return TrustedPartner{}, "連携の有効期限が切れている"
	}
	roots := []*x509.Certificate{root}
	if p.NextRootCert != "" {
		next, err := parseRoot(p.NextRootCert)
		if err != nil {
			return TrustedPartner{}, "次のルート: " + err.Error()
		}
		if !FingerprintEqual(p.NextRootSHA256, Fingerprint(next)) {
			return TrustedPartner{}, "次のルートの指紋が証明書と一致しない"
		}
		for _, own := range o.OwnRoots {
			if own.Equal(next) {
				return TrustedPartner{}, "次のルートが自分のルート CA と同じ"
			}
		}
		roots = append(roots, next)
	}
	return TrustedPartner{ID: p.ID, Root: root, Roots: roots, Domains: scope}, ""
}

// Builder は CA 側でトラストバンドルを作る。連携情報のファイルが変わったとき、
// または有効期限の半分が過ぎたときに作り直す（連番を進める）。
type Builder struct {
	store    *Store
	inter    *x509.Certificate
	key      crypto.Signer
	ownRoots []*x509.Certificate
	ownScope []string
	validity time.Duration
	log      *slog.Logger

	mu         sync.Mutex
	epoch      string
	seq        uint64
	lastIssued time.Time
	compact    string
	etag       string
}

// NewBuilder は Builder を作る。エポックは起動ごとに変わる（バックアップからの復旧で連番が戻っても、
// 各サーバは発行時刻の新しさで受け入れられる。設計 8-1）。
func NewBuilder(store *Store, inter *x509.Certificate, key crypto.Signer, ownRoots []*x509.Certificate, validity time.Duration, log *slog.Logger) (*Builder, error) {
	if validity == 0 {
		validity = DefaultBundleValidity
	}
	if validity < MinBundleValidity || validity > MaxBundleValidity {
		return nil, fmt.Errorf("トラストバンドルの有効期限は %s〜%s", MinBundleValidity, MaxBundleValidity)
	}
	if log == nil {
		log = slog.Default()
	}
	pool := x509.NewCertPool()
	for _, r := range ownRoots {
		pool.AddCert(r)
	}
	ownScope, err := OwnScope(inter, pool, nil)
	if err != nil {
		return nil, err
	}
	e := make([]byte, 16)
	if _, err := rand.Read(e); err != nil {
		return nil, err
	}
	return &Builder{
		store: store, inter: inter, key: key, ownRoots: ownRoots, ownScope: ownScope,
		validity: validity, log: log, epoch: hex.EncodeToString(e),
	}, nil
}

// OwnScope は自分の範囲（中間 CA の名前制約）を返す。
func (b *Builder) OwnScope() []string { return slices.Clone(b.ownScope) }

// OwnRoots は自分のルート CA（CAFile）を返す。
func (b *Builder) OwnRoots() []*x509.Certificate { return slices.Clone(b.ownRoots) }

// Current は現在のバンドル（JWS）と ETag を返す。必要なら作り直す。
func (b *Builder) Current(now time.Time) (string, string, error) {
	f, changed, err := b.store.Snapshot()
	if err != nil {
		return "", "", fmt.Errorf("連携情報のファイルを読めない: %w", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.compact != "" && !changed && now.Before(b.lastIssued.Add(b.validity/2)) {
		return b.compact, b.etag, nil
	}
	issued := now.UTC().Truncate(time.Second)
	if !issued.After(b.lastIssued) {
		issued = b.lastIssued.Add(time.Second)
	}
	bundle := &Bundle{Format: BundleFormat, Epoch: b.epoch, Seq: b.seq + 1, IssuedAt: issued, Expires: issued.Add(b.validity), Partners: []BundlePartner{}}
	for _, r := range b.ownRoots {
		bundle.OwnRoots = append(bundle.OwnRoots, Fingerprint(r))
	}
	var accepted [][]string
	for _, p := range f.Partners {
		if p.State != StateActive {
			continue
		}
		bp := BundlePartner{ID: p.ID, RootCert: p.RootCert, RootSHA256: p.RootSHA256, Domains: p.Domains, Expires: p.Expires}
		if p.NextState == NextActive {
			bp.NextRootCert, bp.NextRootSHA256 = p.NextRootCert, p.NextRootSHA256
		}
		if _, reason := checkPartner(bp, VerifyOptions{OwnRoots: b.ownRoots, OwnScope: b.ownScope, Now: now}, accepted); reason != "" {
			b.log.Warn("連携先をトラストバンドルに入れない", "category", "audit", "partner", p.ID, "reason", reason)
			continue
		}
		if p.Expires.Sub(now) < 30*24*time.Hour {
			b.log.Warn("連携の有効期限が近い（照合と承認をやり直す）", "partner", p.ID, "expires", p.Expires)
		}
		accepted = append(accepted, p.Domains)
		bundle.Partners = append(bundle.Partners, bp)
	}
	compact, err := Sign(bundle, b.inter, b.key)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(compact))
	b.seq, b.lastIssued, b.compact, b.etag = bundle.Seq, issued, compact, `"`+hex.EncodeToString(sum[:16])+`"`
	b.log.Info("トラストバンドルを作った", "epoch", b.epoch, "seq", b.seq, "partners", len(bundle.Partners), "expires", bundle.Expires)
	return b.compact, b.etag, nil
}

// DummyRootPEM は「どこにもつながらない PEM」を作る。自己署名の証明書 1 枚で、秘密鍵は作った直後に捨てる。
// 停止・期限切れの連携先のファイルをこれに置き換えると、nginx などの reload は成功し、連携先からの接続は検証に失敗する（設計 8-2）。
func DummyRootPEM() ([]byte, error) {
	key, err := pki.GenerateKey(pki.KeyECDSAP256)
	if err != nil {
		return nil, err
	}
	root, err := pki.CreateRoot(key, pki.RootOptions{CommonName: "mtls-agent placeholder (trusts nothing)", Validity: 10 * 365 * 24 * time.Hour})
	if err != nil {
		return nil, err
	}
	return pki.EncodeCertsPEM(root), nil
}
