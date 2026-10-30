package federation

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/nobumin/mtls_manager/internal/pki"
)

// ルート CA の入れ替えの予告（設計 11.）。
//   - 連携先は、新しいルート CA を作ったら、古いルート CA の鍵で署名した予告を作る（オフラインの端末で）
//   - 受け取った側は、いま信頼している古いルートで署名を確かめ、新しいルートを「次のルート」として承認待ちに入れる。
//     指紋の照合は不要（古いルートが新しいルートを保証している）。承認は 1 人でよい
//   - 予告で範囲は広げられない（古いルートの範囲を超えない）。予告には有効期限がある
//   - 古いルートの鍵の侵害が理由の入れ替えには、予告を使わない（停止して、初回と同じ連携をやり直す）

// AnnouncementFormat は予告の形式。
const AnnouncementFormat = "mtls-manager-root-announcement/v1"

// MaxAnnouncementValidity は予告の有効期限の上限。
const MaxAnnouncementValidity = 180 * 24 * time.Hour

// 次のルートの状態。
const (
	NextPending = "pending" // 予告を取り込んだ（承認待ち）
	NextActive  = "active"  // 承認した（新旧の両方を信頼する）
)

// Announcement はルート CA の入れ替えの予告。古いルート CA の鍵で署名した JWS（compact）として渡す。
type Announcement struct {
	Format string `json:"format"`
	// OldRootSHA256 は連携先の識別に使う、いまのルート CA の指紋。
	OldRootSHA256 string `json:"old_root_sha256"`
	NewRootCert   string `json:"new_root_cert"`
	NewRootSHA256 string `json:"new_root_sha256"`
	// Domains は新しいルートの範囲。受け取る側が承認している相手の申告の範囲を超えてはならない。
	Domains   []string  `json:"domains"`
	SwitchAt  time.Time `json:"switch_at"`
	CreatedAt time.Time `json:"created_at"`
	Expires   time.Time `json:"expires"`
}

// NewAnnouncement は予告を作る（未署名）。
func NewAnnouncement(oldRoot, newRoot *x509.Certificate, domains []string, switchAt time.Time, validity time.Duration, now time.Time) (*Announcement, error) {
	if err := CheckRoot(newRoot); err != nil {
		return nil, fmt.Errorf("新しいルート CA: %w", err)
	}
	if oldRoot.Equal(newRoot) {
		return nil, errors.New("新しいルート CA が古いものと同じ")
	}
	ds, err := NormalizeScope(domains)
	if err != nil {
		return nil, err
	}
	if validity <= 0 || validity > MaxAnnouncementValidity {
		return nil, fmt.Errorf("予告の有効期限は %s まで", MaxAnnouncementValidity)
	}
	now = now.UTC().Truncate(time.Second)
	return &Announcement{
		Format: AnnouncementFormat, OldRootSHA256: Fingerprint(oldRoot),
		NewRootCert: string(pki.EncodeCertsPEM(newRoot)), NewRootSHA256: Fingerprint(newRoot),
		Domains: ds, SwitchAt: switchAt.UTC().Truncate(time.Second), CreatedAt: now, Expires: now.Add(validity),
	}, nil
}

// SignAnnouncement は予告に古いルート CA の鍵で署名する。
func SignAnnouncement(a *Announcement, oldRoot *x509.Certificate, oldRootKey crypto.Signer) (string, error) {
	if !pki.PublicKeyEqual(oldRoot.PublicKey, oldRootKey.Public()) {
		return "", errors.New("古いルート CA の証明書と鍵が対応していない")
	}
	alg, err := algFor(oldRootKey)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: oldRootKey}, nil)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

// VerifyAnnouncement は予告の署名を、いま信頼している古いルート CA で確かめ、内容を検証する。
func VerifyAnnouncement(compact string, oldRoot *x509.Certificate, now time.Time) (*Announcement, *x509.Certificate, error) {
	jws, err := jose.ParseSigned(compact, signingAlgs)
	if err != nil {
		return nil, nil, fmt.Errorf("予告を解釈できない: %w", err)
	}
	payload, err := jws.Verify(oldRoot.PublicKey)
	if err != nil {
		return nil, nil, errors.New("予告の署名を、いま信頼しているルート CA で確かめられない")
	}
	var a Announcement
	if err := json.Unmarshal(payload, &a); err != nil {
		return nil, nil, fmt.Errorf("予告を解釈できない: %w", err)
	}
	if a.Format != AnnouncementFormat {
		return nil, nil, fmt.Errorf("予告の形式 %q に対応していない", a.Format)
	}
	if !FingerprintEqual(a.OldRootSHA256, Fingerprint(oldRoot)) {
		return nil, nil, errors.New("予告の古いルート CA の指紋が、いま信頼しているものと違う")
	}
	if a.CreatedAt.IsZero() || !a.Expires.After(a.CreatedAt) || a.Expires.Sub(a.CreatedAt) > MaxAnnouncementValidity {
		return nil, nil, errors.New("予告の作成日時・有効期限が不正")
	}
	if !now.Before(a.Expires) {
		return nil, nil, errors.New("予告の有効期限が切れている（古い予告の再送は受け付けない）")
	}
	newRoot, err := parseRoot(a.NewRootCert)
	if err != nil {
		return nil, nil, fmt.Errorf("新しいルート CA: %w", err)
	}
	if !FingerprintEqual(a.NewRootSHA256, Fingerprint(newRoot)) {
		return nil, nil, errors.New("新しいルート CA の指紋が証明書と一致しない")
	}
	if newRoot.Equal(oldRoot) {
		return nil, nil, errors.New("新しいルート CA が古いものと同じ")
	}
	if a.Domains, err = NormalizeScope(a.Domains); err != nil {
		return nil, nil, err
	}
	return &a, newRoot, nil
}

// ImportAnnouncement は連携先のルート CA の入れ替えの予告を取り込み、新しいルートを承認待ちにする。
// 有効な連携先だけが対象で、署名はいま信頼している（承認済みの）ルート CA で確かめる。
// ownRoots は自分のルート CA（CAFile。入れ替え中は新旧の 2 つ）で、新しいルートがこれと同じ予告は拒否する。
// 次のルートがすでにある（承認待ち・承認済み）ときも拒否する（黙って置き換えない。先に取り消す）。
func (f *File) ImportAnnouncement(id, compact string, ownRoots []*x509.Certificate, by Actor, now time.Time) error {
	if len(ownRoots) == 0 {
		return errors.New("自分のルート CA が無い")
	}
	p := f.Find(id)
	if p == nil {
		return fmt.Errorf("連携先 %q が無い", id)
	}
	if p.State != StateActive {
		return fmt.Errorf("連携先 %q は %s の状態（予告は有効な連携先にだけ使える。停止中なら初回と同じ連携をやり直す）", id, p.State)
	}
	if p.NextState != "" {
		return fmt.Errorf("連携先 %q には次のルート（%s の状態）がすでにある（別の予告を取り込むなら、先に次のルートを取り消す（cancel-next））", id, p.NextState)
	}
	oldRoot, err := p.Root()
	if err != nil {
		return err
	}
	a, newRoot, err := VerifyAnnouncement(compact, oldRoot, now)
	if err != nil {
		return err
	}
	for _, own := range ownRoots {
		if own.Equal(newRoot) {
			return errors.New("新しいルート CA が、自分のルート CA と同じ")
		}
	}
	// 予告で範囲は広げられない（相手の申告の範囲を超えない）。承認している範囲は変えない。
	if !WithinScope(a.Domains, p.DeclaredDomains) {
		return fmt.Errorf("予告の範囲 %v が、これまでの範囲 %v を超える（範囲を広げるなら、初回と同じ照合と 2 人の承認を行う）", a.Domains, p.DeclaredDomains)
	}
	for _, q := range f.Partners {
		if FingerprintEqual(q.RootSHA256, a.NewRootSHA256) || FingerprintEqual(q.NextRootSHA256, a.NewRootSHA256) {
			return fmt.Errorf("新しいルート CA は、すでに連携先 %q のルートとしてある", q.ID)
		}
	}
	p.NextRootCert, p.NextRootSHA256, p.NextState = string(pki.EncodeCertsPEM(newRoot)), a.NewRootSHA256, NextPending
	p.NextSwitchAt, p.NextExpires = a.SwitchAt, a.Expires
	p.record("announce", by, "次のルート "+a.NewRootSHA256, now)
	return nil
}

// ApproveNext は次のルートを承認する（1 人でよい。古いルートが新しいルートを保証しているため）。
// 承認すると、新旧の両方のルートを同じ範囲で信頼する。
func (f *File) ApproveNext(id string, by Actor, now time.Time) error {
	p := f.Find(id)
	if p == nil {
		return fmt.Errorf("連携先 %q が無い", id)
	}
	if p.NextState != NextPending {
		return fmt.Errorf("連携先 %q に承認待ちの次のルートが無い", id)
	}
	if !now.Before(p.NextExpires) {
		return errors.New("予告の有効期限が切れている（予告を取り込み直す）")
	}
	p.NextState = NextActive
	p.record("approve-next", by, "次のルート "+p.NextRootSHA256, now)
	return nil
}

// RetireRoot は古いルートを外し、次のルートを今のルートにする（相手が新しいルートで発行し始めた後）。
// 信頼を狭める操作なので 1 人でよい。
func (f *File) RetireRoot(id string, by Actor, now time.Time) error {
	p := f.Find(id)
	if p == nil {
		return fmt.Errorf("連携先 %q が無い", id)
	}
	if p.NextState != NextActive {
		return fmt.Errorf("連携先 %q に承認済みの次のルートが無い", id)
	}
	old := p.RootSHA256
	p.RootCert, p.RootSHA256 = p.NextRootCert, p.NextRootSHA256
	p.clearNext()
	p.record("retire-root", by, "古いルート "+old+" を外した", now)
	return nil
}

// CancelNext は次のルートを取り消す。
func (f *File) CancelNext(id string, by Actor, now time.Time) error {
	p := f.Find(id)
	if p == nil {
		return fmt.Errorf("連携先 %q が無い", id)
	}
	if p.NextState == "" {
		return fmt.Errorf("連携先 %q に次のルートが無い", id)
	}
	fp := p.NextRootSHA256
	p.clearNext()
	p.record("cancel-next", by, "次のルート "+fp+" を取り消した", now)
	return nil
}

func (p *Partner) clearNext() {
	p.NextRootCert, p.NextRootSHA256, p.NextState = "", "", ""
	p.NextSwitchAt, p.NextExpires = time.Time{}, time.Time{}
}
