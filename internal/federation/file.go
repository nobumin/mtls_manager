package federation

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/nobumin/mtls_manager/internal/flock"
	"github.com/nobumin/mtls_manager/internal/pki"
)

// 連携先の状態。
const (
	StatePending   = "pending"   // 取り込んだだけ（照合も申請もしていない）
	StateRequested = "requested" // 1 人目が照合して承認を申請した
	StateActive    = "active"    // 2 人目が承認した（トラストバンドルに入る）
	StateSuspended = "suspended" // 停止した（再開には照合と 2 人の承認をやり直す）
)

// 操作した経路。
const (
	// ViaAdmin は管理画面（管理者の名前は mTLS の証明書で確かめたもの）。
	ViaAdmin = "admin-ui"
	// ViaCLI は mtlsctl（管理者の名前は自己申告）。
	ViaCLI = "cli"
)

// Actor は操作した管理者と経路。
type Actor struct {
	Name string
	Via  string
}

// ByAdmin は管理画面からの操作（名前は mTLS の証明書で確かめたもの）。
func ByAdmin(name string) Actor { return Actor{Name: name, Via: ViaAdmin} }

// ByCLI は mtlsctl からの操作（名前は自己申告）。
func ByCLI(name string) Actor { return Actor{Name: name, Via: ViaCLI} }

// viaOrCLI は経路を返す（記録の無い古い操作は CLI とみなす）。
func viaOrCLI(v string) string {
	if v == "" {
		return ViaCLI
	}
	return v
}

// Verified は、名前を mTLS の証明書で確かめた操作かを返す。
func (a Actor) Verified() bool { return a.Via == ViaAdmin }

// DefaultPartnerValidity は連携の有効期限の既定（1 年）。
const DefaultPartnerValidity = 365 * 24 * time.Hour

// Partner は連携先 1 件。
type Partner struct {
	// ID は自分の側で付ける識別子（ファイル名に使う。相手の申告は使わない）。
	ID    string `json:"id"`
	State string `json:"state"`

	// Organization と Contacts は相手の申告（未検証）。表示の参考にするだけ。
	Organization string   `json:"organization,omitempty"`
	Contacts     []string `json:"contacts,omitempty"`

	RootCert   string `json:"root_cert"`
	RootSHA256 string `json:"root_sha256"`
	// DeclaredDomains は相手が申告した範囲（承認できる範囲の上限）。
	DeclaredDomains []string `json:"declared_domains"`
	// Domains は承認した範囲（DeclaredDomains を狭めたもの）。申請の前は空。
	Domains []string `json:"domains,omitempty"`

	// ComparedWith は指紋を照合した相手と経路（ファイルとは無関係に前もって知っている連絡先）。
	ComparedWith string    `json:"compared_with,omitempty"`
	RequestedBy  string    `json:"requested_by,omitempty"`
	RequestedVia string    `json:"requested_via,omitempty"`
	RequestedAt  time.Time `json:"requested_at,omitzero"`
	ApprovedBy   string    `json:"approved_by,omitempty"`
	ApprovedVia  string    `json:"approved_via,omitempty"`
	ApprovedAt   time.Time `json:"approved_at,omitzero"`
	// Expires は連携の有効期限。過ぎたらバンドルに入れない（照合と承認をやり直す）。
	Expires time.Time `json:"expires,omitzero"`

	ImportedAt time.Time `json:"imported_at"`
	Events     []Event   `json:"events,omitempty"`
}

// Event は連携先に対する操作の記録。
type Event struct {
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	By     string    `json:"by"`
	Via    string    `json:"via,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// Root は連携先のルート CA の証明書を返す。
func (p *Partner) Root() (*x509.Certificate, error) { return parseRoot(p.RootCert) }

func (p *Partner) record(action string, by Actor, detail string, now time.Time) {
	p.Events = append(p.Events, Event{At: now.UTC().Truncate(time.Second), Action: action, By: by.Name, Via: by.Via, Detail: detail})
}

// File は連携情報のファイル（federation.file）の中身。秘密情報は含まない。
type File struct {
	Partners []Partner `json:"partners"`
}

// Find は ID の連携先を返す。
func (f *File) Find(id string) *Partner {
	for i := range f.Partners {
		if f.Partners[i].ID == id {
			return &f.Partners[i]
		}
	}
	return nil
}

// Import は連携先の連携情報を取り込む（承認待ち）。ID は自分の側で付ける。
// 同じルート CA・同じ ID の連携先がすでにあれば拒否する。
func (f *File) Import(id string, rec *Record, root *x509.Certificate, now time.Time, by Actor) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	if f.Find(id) != nil {
		return fmt.Errorf("連携先 %q はすでにある", id)
	}
	fp := Fingerprint(root)
	for _, p := range f.Partners {
		if FingerprintEqual(p.RootSHA256, fp) {
			return fmt.Errorf("このルート CA はすでに連携先 %q として取り込んである", p.ID)
		}
	}
	p := Partner{
		ID: id, State: StatePending, Organization: rec.Organization, Contacts: rec.Contacts,
		RootCert: string(pki.EncodeCertsPEM(root)), RootSHA256: fp, DeclaredDomains: rec.Domains,
		ImportedAt: now.UTC().Truncate(time.Second),
	}
	p.record("import", by, "指紋 "+fp, now)
	f.Partners = append(f.Partners, p)
	return nil
}

// RequestOptions は承認の申請（1 人目）の内容。
type RequestOptions struct {
	// Fingerprint は照合のときに読み上げを聞いて入力した指紋の全体（64 桁）。
	Fingerprint string
	// ComparedWith は照合した相手と経路（例: 「契約書記載の○○部 △△ 氏、電話」）。
	ComparedWith string
	// Domains は承認する範囲。空なら相手の申告どおり。申告より広くはできない。
	Domains []string
	// Validity は連携の有効期限までの期間。0 なら 1 年。
	Validity time.Duration
	By       Actor
}

// Request は 1 人目の管理者による承認の申請（設計 7-4 の 1.）。
// ownScope は自分の範囲（重なりの確認に使う）。
func (f *File) Request(id string, o RequestOptions, ownScope []string, now time.Time) error {
	p := f.Find(id)
	if p == nil {
		return fmt.Errorf("連携先 %q が無い", id)
	}
	if p.State != StatePending && p.State != StateSuspended {
		return fmt.Errorf("連携先 %q は %s の状態なので申請できない（pending か suspended のときだけ）", id, p.State)
	}
	if NormalizeFingerprint(o.Fingerprint) == "" {
		return errors.New("指紋は全体（64 桁の 16 進）を入力する")
	}
	if !FingerprintEqual(o.Fingerprint, p.RootSHA256) {
		return errors.New("入力した指紋が、取り込んだルート CA の指紋と一致しない（照合をやり直す）")
	}
	if o.ComparedWith == "" {
		return errors.New("照合した相手と経路（ファイルとは無関係に前もって知っている連絡先）を入力する")
	}
	if o.By.Name == "" {
		return errors.New("申請する管理者の名前が無い")
	}
	scope := p.DeclaredDomains
	if len(o.Domains) > 0 {
		s, err := NormalizeScope(o.Domains)
		if err != nil {
			return err
		}
		if !WithinScope(s, p.DeclaredDomains) {
			return fmt.Errorf("範囲 %v は、相手の申告 %v より広い（狭めることだけができる）", s, p.DeclaredDomains)
		}
		scope = s
	}
	if err := f.checkScope(id, scope, ownScope); err != nil {
		return err
	}
	validity := o.Validity
	if validity == 0 {
		validity = DefaultPartnerValidity
	}
	if validity < 24*time.Hour || validity > 2*DefaultPartnerValidity {
		return errors.New("連携の有効期限は 1 日〜2 年")
	}
	p.State, p.Domains, p.ComparedWith = StateRequested, scope, o.ComparedWith
	p.RequestedBy, p.RequestedVia, p.RequestedAt = o.By.Name, o.By.Via, now.UTC().Truncate(time.Second)
	p.ApprovedBy, p.ApprovedVia, p.ApprovedAt = "", "", time.Time{}
	p.Expires = now.Add(validity).UTC().Truncate(time.Second)
	p.record("request", o.By, fmt.Sprintf("範囲 %v、照合 %s", scope, o.ComparedWith), now)
	return nil
}

// Approve は 2 人目の管理者による承認（設計 7-4 の 2.）。申請者と同じ管理者は承認できない。
// 承認者も指紋の全体を入力する（申請の内容を確かめたことの確認）。
func (f *File) Approve(id, fingerprint string, by Actor, ownScope []string, now time.Time) error {
	p := f.Find(id)
	if p == nil {
		return fmt.Errorf("連携先 %q が無い", id)
	}
	if p.State != StateRequested {
		return fmt.Errorf("連携先 %q は %s の状態なので承認できない（申請の後だけ）", id, p.State)
	}
	if by.Name == "" {
		return errors.New("承認する管理者の名前が無い")
	}
	// 承認は申請と同じ経路で行う。画面の名前（証明書）と CLI の名前（自己申告）は別の名前空間なので、
	// 経路をまたぐと、同じ人でも別の名前に見えて 2 人の承認を 1 人で通せてしまう。
	if reqVia := viaOrCLI(p.RequestedVia); viaOrCLI(by.Via) != reqVia {
		if reqVia == ViaCLI {
			return errors.New("申請と同じ経路で承認する（この連携先は CLI で申請されたので、CLI で承認するか、停止してから管理画面で申請し直す）")
		}
		return errors.New("申請と同じ経路で承認する（この連携先は管理画面で申請されたので、管理画面で承認する）")
	}
	if by.Name == p.RequestedBy {
		return fmt.Errorf("申請した管理者（%s）とは別の管理者が承認する", by.Name)
	}
	if !FingerprintEqual(fingerprint, p.RootSHA256) {
		return errors.New("入力した指紋が、取り込んだルート CA の指紋と一致しない")
	}
	if err := f.checkScope(id, p.Domains, ownScope); err != nil {
		return err
	}
	if !now.Before(p.Expires) {
		return errors.New("申請した連携の有効期限が過ぎている（申請をやり直す）")
	}
	p.State, p.ApprovedBy, p.ApprovedVia, p.ApprovedAt = StateActive, by.Name, by.Via, now.UTC().Truncate(time.Second)
	p.record("approve", by, fmt.Sprintf("範囲 %v", p.Domains), now)
	return nil
}

// Suspend は連携を停止する。1 人で即時にできる（守る側の操作なので）。
func (f *File) Suspend(id string, by Actor, reason string, now time.Time) error {
	p := f.Find(id)
	if p == nil {
		return fmt.Errorf("連携先 %q が無い", id)
	}
	if p.State == StateSuspended {
		return fmt.Errorf("連携先 %q はすでに停止している", id)
	}
	p.State = StateSuspended
	p.record("suspend", by, reason, now)
	return nil
}

// Remove は連携先を消す。有効な連携先は、先に停止してから消す。
func (f *File) Remove(id string) error {
	p := f.Find(id)
	if p == nil {
		return fmt.Errorf("連携先 %q が無い", id)
	}
	if p.State == StateActive {
		return fmt.Errorf("連携先 %q は有効なので、先に停止する", id)
	}
	f.Partners = slices.DeleteFunc(f.Partners, func(q Partner) bool { return q.ID == id })
	return nil
}

// checkScope は、範囲が自分の範囲・他の連携先（申請中・有効なもの）の範囲と重ならないことを確かめる。
func (f *File) checkScope(id string, scope, ownScope []string) error {
	if len(ownScope) == 0 {
		return errors.New("自分の範囲が決まらないので、重なりを確かめられない")
	}
	if ScopesOverlap(scope, ownScope) {
		return fmt.Errorf("範囲 %v が自分の範囲 %v と重なる", scope, ownScope)
	}
	for _, q := range f.Partners {
		if q.ID == id || (q.State != StateActive && q.State != StateRequested) {
			continue
		}
		if ScopesOverlap(scope, q.Domains) {
			return fmt.Errorf("範囲 %v が連携先 %q の範囲 %v と重なる", scope, q.ID, q.Domains)
		}
	}
	return nil
}

// Load は連携情報のファイルを読む。
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

// LoadOrEmpty はファイルが無ければ空の File を返す。
func LoadOrEmpty(path string) (*File, error) {
	f, err := Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return &File{}, nil
	}
	return f, err
}

// Save はファイルを書く（一時ファイルから rename）。秘密情報は含まないので 0644。
func (f *File) Save(path string) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return pki.WriteFileAtomic(path, append(data, '\n'), 0o644)
}

// Update はファイルを排他ロックの下で読み、fn で変更して書き戻す（無ければ空から作る）。
func Update(path string, fn func(*File) error) error {
	unlock, err := flock.Lock(path)
	if err != nil {
		return fmt.Errorf("%s をロックできない: %w", path, err)
	}
	defer unlock()
	f, err := LoadOrEmpty(path)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		return err
	}
	return f.Save(path)
}

// Store は CA が連携情報のファイルを参照するためのもの。ファイルの更新（mtlsctl federation）を再起動なしで反映する。
type Store struct {
	path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	file    *File
}

// NewStore はファイルを読み込んで Store を作る（無ければ空）。
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	if _, _, err := s.Snapshot(); err != nil {
		return nil, err
	}
	return s, nil
}

// Snapshot は現在の内容と、前回から変わったかを返す。読み直しに失敗したらエラー（古い内容で信頼し続けない）。
func (s *Store) Snapshot() (*File, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fi, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		changed := s.file == nil || len(s.file.Partners) > 0
		s.file, s.modTime, s.size = &File{}, time.Time{}, 0
		return s.file, changed, nil
	}
	if err != nil {
		return nil, false, err
	}
	if s.file != nil && fi.ModTime().Equal(s.modTime) && fi.Size() == s.size {
		return s.file, false, nil
	}
	f, err := Load(s.path)
	if err != nil {
		return nil, false, err
	}
	s.file, s.modTime, s.size = f, fi.ModTime(), fi.Size()
	return f, true, nil
}
