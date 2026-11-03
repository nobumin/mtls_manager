package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/federation"
	"github.com/nobumin/mtls_manager/internal/i18n"
	"github.com/nobumin/mtls_manager/internal/pki"
)

// 連携版（別々の mtls-ca で管理するサーバ間の mTLS）の連携先の管理。設計は docs/ja/federation-design.md。
// 連携情報のファイル（CA の federation.file）を、ロックの下で書き換える。CA の再起動は不要。

// fedEnv は CA の設定から、連携情報のファイルと自分の範囲・ルート CA を得る。
type fedEnv struct {
	file     string
	roots    []*x509.Certificate
	ownScope []string
}

func loadFedEnv(configPath string) (*fedEnv, error) {
	if configPath == "" {
		return nil, errors.New(i18n.T("-config（mtls-ca の設定ファイル）は必須", "-config (the mtls-ca configuration file) is required"))
	}
	cfg, err := config.LoadCA(configPath)
	if err != nil {
		return nil, err
	}
	if cfg.Federation.File == "" {
		return nil, errors.New(i18n.T("CA の設定に federation.file が無い（連携版を使うには設定する）", "the CA configuration has no federation.file (set it to use federation)"))
	}
	roots, err := pki.LoadCerts(cfg.RootCert)
	if err != nil {
		return nil, fmt.Errorf("root_cert: %w", err)
	}
	inter, err := pki.LoadCert(cfg.IntermediateCert)
	if err != nil {
		return nil, fmt.Errorf("intermediate_cert: %w", err)
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	scope, err := federation.OwnScope(inter, pool, nil)
	if err != nil {
		return nil, err
	}
	return &fedEnv{file: cfg.Federation.File, roots: roots, ownScope: scope}, nil
}

// operator は操作した管理者の名前（-by。省略時は SUDO_USER / USER）。
// 段階 1 の CLI では自己申告で、2 人の承認は「別の名前」であることだけを確かめる。
// 本人の確認（mTLS の証明書による）は、段階 2 の管理画面で行う。
func operator(by string) (string, error) {
	for _, v := range []string{by, os.Getenv("SUDO_USER"), os.Getenv("USER")} {
		if v = strings.TrimSpace(v); v != "" && v != "root" {
			return v, nil
		}
	}
	return "", errors.New(i18n.T("操作する管理者の名前を -by で指定する", "specify the operating administrator's name with -by"))
}

// fingerprintInput は指紋を得る。-fingerprint が無ければ、端末から入力させる（照合のときの読み上げを聞いて入力する）。
func fingerprintInput(v string) (string, error) {
	if v != "" {
		return v, nil
	}
	fmt.Fprint(os.Stderr, i18n.T("照合した指紋の全体（64 桁の 16 進。区切りのコロンは省略可）を入力: ", "Enter the full fingerprint you compared (64 hex digits; separating colons are optional): "))
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New(i18n.T("指紋が入力されなかった", "no fingerprint was entered"))
	}
	return strings.TrimSpace(line), nil
}

func fedExport(args []string) error {
	fs := newFlags("federation export")
	configPath := fs.String("config", "", i18n.T("mtls-ca の設定ファイル", "mtls-ca configuration file"))
	org := fs.String("org", "", i18n.T("組織の名前（相手には未検証の参考情報として表示される）", "organization name (shown to the partner as unverified reference information)"))
	var contacts, domains []string
	fs.Var(listFlag{&contacts}, "contacts", i18n.T("連絡先（参考情報。相手は照合には使わない）", "contacts (reference information; the partner does not use them for comparison)"))
	fs.Var(listFlag{&domains}, "domains", i18n.T("相手に申告する範囲（省略時は中間 CA の名前制約。狭めることだけができる）", "scope to declare to the partner (default: the intermediate CA's name constraints; can only be narrowed)"))
	out := fs.String("out", "", i18n.T("書き出すファイル（省略時は画面）", "output file (default: the screen)"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	env, err := loadFedEnv(*configPath)
	if err != nil {
		return err
	}
	if len(env.roots) != 1 {
		return fmt.Errorf(i18n.T("root_cert にルート CA が %d 枚ある（入れ替え中は、相手に渡すルートを 1 枚にしたファイルで書き出す）", "root_cert contains %d root CAs (during a rotation, export with a file containing only the root to give to the partner)"), len(env.roots))
	}
	scope := env.ownScope
	if len(domains) > 0 {
		if scope, err = federation.NormalizeScope(domains); err != nil {
			return err
		}
		if !federation.WithinScope(scope, env.ownScope) {
			return fmt.Errorf(i18n.T("範囲 %v が中間 CA の名前制約 %v より広い", "scope %v is wider than the intermediate CA's name constraints %v"), scope, env.ownScope)
		}
	}
	rec, err := federation.NewRecord(env.roots[0], scope, *org, contacts)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *out == "" {
		_, err = os.Stdout.Write(data)
	} else {
		err = pki.WriteFileAtomic(*out, data, 0o644)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, i18n.T("連携情報を書き出した（秘密情報は含まない）。\n指紋: %s\n相手とは、この指紋の全体を、ファイルとは別の経路で読み合わせる。\n", "exported the federation record (it contains no secrets).\nFingerprint: %s\nRead the full fingerprint aloud with the partner over a channel separate from the file.\n"), rec.RootSHA256)
	return nil
}

func fedImport(args []string) error {
	fs := newFlags("federation import")
	configPath := fs.String("config", "", i18n.T("mtls-ca の設定ファイル", "mtls-ca configuration file"))
	in := fs.String("in", "", i18n.T("連携先から受け取った連携情報のファイル", "federation record file received from the partner"))
	id := fs.String("id", "", i18n.T("この連携先に自分の側で付ける識別子（[a-z0-9-]、1〜32 文字。ファイル名に使う）", "your own identifier for this partner ([a-z0-9-], 1 to 32 characters; used in file names)"))
	by := fs.String("by", "", i18n.T("操作する管理者の名前", "name of the operating administrator"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("in", *in, "id", *id); err != nil {
		return err
	}
	env, err := loadFedEnv(*configPath)
	if err != nil {
		return err
	}
	who, err := operator(*by)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	rec, root, err := federation.ParseRecord(data)
	if err != nil {
		return err
	}
	if err := federation.Update(env.file, func(f *federation.File) error { return f.Import(*id, rec, root, time.Now(), federation.ByCLI(who)) }); err != nil {
		return err
	}
	fmt.Printf(i18n.T(`連携先 %s を取り込んだ（承認待ち。まだ信頼しない）。
  指紋:            %s
  申告された範囲:  %v
  組織・連絡先:    %s %v（未検証。相手の申告で、照合の相手を決めるのには使わない）

次の手順:
  1. 指紋の全体を、ファイルとは無関係に前もって知っている連絡先（契約書の窓口など）と、別の経路で読み合わせる
  2. mtlsctl federation request -config ... -id %s -compared-with "照合した相手と経路"   （1 人目）
  3. mtlsctl federation approve -config ... -id %s                                       （別の管理者）
`, `imported partner %s (pending approval; not trusted yet).
  Fingerprint:      %s
  Declared scope:   %v
  Org / contacts:   %s %v (unverified; declared by the partner, not used to choose whom to compare with)

Next steps:
  1. Read the full fingerprint aloud with a contact you knew beforehand, independent of the file (e.g. the contact named in your contract), over a separate channel
  2. mtlsctl federation request -config ... -id %s -compared-with "who you compared with and how"   (first administrator)
  3. mtlsctl federation approve -config ... -id %s                                                  (another administrator)
`), *id, federation.Fingerprint(root), rec.Domains, rec.Organization, rec.Contacts, *id, *id)
	return nil
}

func fedRequest(args []string) error {
	fs := newFlags("federation request")
	configPath := fs.String("config", "", i18n.T("mtls-ca の設定ファイル", "mtls-ca configuration file"))
	id := fs.String("id", "", i18n.T("連携先の識別子", "partner identifier"))
	fp := fs.String("fingerprint", "", i18n.T("照合した指紋の全体（省略時は入力を求める）", "full fingerprint you compared (prompted if omitted)"))
	compared := fs.String("compared-with", "", i18n.T("照合した相手と経路（例: 契約書記載の○○部 △△ 氏、電話）", "who you compared with and how (e.g. Jane Doe, IT dept. named in the contract, by phone)"))
	var domains []string
	fs.Var(listFlag{&domains}, "domains", i18n.T("承認する範囲（省略時は相手の申告どおり。狭めることだけができる）", "scope to approve (default: as declared by the partner; can only be narrowed)"))
	var validity time.Duration
	fs.Var(durationFlag{&validity}, "validity", i18n.T("連携の有効期限（既定 1y）", "federation expiry (default 1y)"))
	by := fs.String("by", "", i18n.T("申請する管理者の名前", "name of the requesting administrator"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("id", *id, "compared-with", *compared); err != nil {
		return err
	}
	env, err := loadFedEnv(*configPath)
	if err != nil {
		return err
	}
	who, err := operator(*by)
	if err != nil {
		return err
	}
	fingerprint, err := fingerprintInput(*fp)
	if err != nil {
		return err
	}
	o := federation.RequestOptions{Fingerprint: fingerprint, ComparedWith: *compared, Domains: domains, Validity: validity, By: federation.ByCLI(who)}
	var p federation.Partner
	if err := federation.Update(env.file, func(f *federation.File) error {
		if err := f.Request(*id, o, env.ownScope, time.Now()); err != nil {
			return err
		}
		p = *f.Find(*id)
		return nil
	}); err != nil {
		return err
	}
	fmt.Printf(i18n.T("連携先 %s の承認を申請した（申請者 %s）。\n  範囲:     %v\n  有効期限: %s\n別の管理者が mtlsctl federation approve で承認すると、トラストバンドルに入る。\n", "requested approval of partner %s (requested by %s).\n  Scope:   %v\n  Expires: %s\nIt enters the trust bundle once another administrator approves it with mtlsctl federation approve.\n"),
		*id, who, p.Domains, p.Expires.Local().Format(time.RFC3339))
	return nil
}

func fedApprove(args []string) error {
	fs := newFlags("federation approve")
	configPath := fs.String("config", "", i18n.T("mtls-ca の設定ファイル", "mtls-ca configuration file"))
	id := fs.String("id", "", i18n.T("連携先の識別子", "partner identifier"))
	fp := fs.String("fingerprint", "", i18n.T("指紋の全体（省略時は入力を求める）", "full fingerprint (prompted if omitted)"))
	by := fs.String("by", "", i18n.T("承認する管理者の名前（申請者とは別の人）", "name of the approving administrator (someone other than the requester)"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("id", *id); err != nil {
		return err
	}
	env, err := loadFedEnv(*configPath)
	if err != nil {
		return err
	}
	who, err := operator(*by)
	if err != nil {
		return err
	}
	fingerprint, err := fingerprintInput(*fp)
	if err != nil {
		return err
	}
	if err := federation.Update(env.file, func(f *federation.File) error {
		return f.Approve(*id, fingerprint, federation.ByCLI(who), env.ownScope, time.Now())
	}); err != nil {
		return err
	}
	fmt.Printf(i18n.T("連携先 %s を承認した（承認者 %s）。各サーバには、次のトラストバンドルの取得（既定 1 分以内）で届く。\n", "approved partner %s (approved by %s). Servers receive it with the next trust bundle fetch (within 1 minute by default).\n"), *id, who)
	return nil
}

func fedSuspend(args []string) error {
	fs := newFlags("federation suspend")
	configPath := fs.String("config", "", i18n.T("mtls-ca の設定ファイル", "mtls-ca configuration file"))
	id := fs.String("id", "", i18n.T("連携先の識別子", "partner identifier"))
	reason := fs.String("reason", "", i18n.T("理由", "reason"))
	by := fs.String("by", "", i18n.T("操作する管理者の名前", "name of the operating administrator"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("id", *id); err != nil {
		return err
	}
	env, err := loadFedEnv(*configPath)
	if err != nil {
		return err
	}
	who, err := operator(*by)
	if err != nil {
		return err
	}
	if err := federation.Update(env.file, func(f *federation.File) error { return f.Suspend(*id, federation.ByCLI(who), *reason, time.Now()) }); err != nil {
		return err
	}
	fmt.Printf(i18n.T("連携先 %s を停止した。各サーバには次のトラストバンドルの取得（既定 1 分以内）で届く。\n", "suspended partner %s. Servers receive it with the next trust bundle fetch (within 1 minute by default).\n")+
		i18n.T("CA と各サーバの通信が妨げられている場合、最悪はバンドルの有効期限（既定 2 日）まで信頼が残る。急ぐ場合は各アプリの AllowedPeers からも外す。\n", "If traffic between the CA and the servers is blocked, trust may remain until the bundle expires (2 days by default) in the worst case. In urgent cases, also remove the partner from each application's AllowedPeers.\n"), *id)
	return nil
}

func fedRemove(args []string) error {
	fs := newFlags("federation remove")
	configPath := fs.String("config", "", i18n.T("mtls-ca の設定ファイル", "mtls-ca configuration file"))
	id := fs.String("id", "", i18n.T("連携先の識別子（有効なものは先に停止する）", "partner identifier (suspend an active partner first)"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("id", *id); err != nil {
		return err
	}
	env, err := loadFedEnv(*configPath)
	if err != nil {
		return err
	}
	if err := federation.Update(env.file, func(f *federation.File) error { return f.Remove(*id) }); err != nil {
		return err
	}
	fmt.Printf(i18n.T("連携先 %s を消した\n", "removed partner %s\n"), *id)
	return nil
}

func fedList(args []string) error {
	fs := newFlags("federation list")
	configPath := fs.String("config", "", i18n.T("mtls-ca の設定ファイル", "mtls-ca configuration file"))
	id := fs.String("id", "", i18n.T("指定すると、その連携先の詳細と操作の記録を表示する", "if set, show that partner's details and operation history"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	env, err := loadFedEnv(*configPath)
	if err != nil {
		return err
	}
	f, err := federation.LoadOrEmpty(env.file)
	if err != nil {
		return err
	}
	fmt.Printf(i18n.T("自分の範囲（中間 CA の名前制約）: %v\n\n", "Own scope (the intermediate CA's name constraints): %v\n\n"), env.ownScope)
	if *id != "" {
		p := f.Find(*id)
		if p == nil {
			return fmt.Errorf(i18n.T("連携先 %q が無い", "no partner %q"), *id)
		}
		next := "-"
		if p.NextState != "" {
			next = fmt.Sprintf(i18n.T("%s（%s、切り替えの予定日 %s）", "%s (%s, planned switch %s)"), p.NextRootSHA256, p.NextState, fmtTime(p.NextSwitchAt))
		}
		fmt.Printf(i18n.T("ID:             %s\n状態:           %s\n指紋:           %s\n申告された範囲: %v\n承認した範囲:   %v\n組織・連絡先:   %s %v（未検証）\n照合した相手:   %s\n申請:           %s %s\n承認:           %s %s\n有効期限:       %s\n次のルート:     %s\n\n操作の記録:\n", "ID:               %s\nState:            %s\nFingerprint:      %s\nDeclared scope:   %v\nApproved scope:   %v\nOrg / contacts:   %s %v (unverified)\nCompared with:    %s\nRequested by:     %s %s\nApproved by:      %s %s\nExpires:          %s\nNext root:        %s\n\nOperation history:\n"),
			p.ID, p.State, p.RootSHA256, p.DeclaredDomains, p.Domains, p.Organization, p.Contacts, p.ComparedWith,
			p.RequestedBy, fmtTime(p.RequestedAt), p.ApprovedBy, fmtTime(p.ApprovedAt), fmtTime(p.Expires), next)
		for _, e := range p.Events {
			via := i18n.T("CLI・自己申告", "CLI, self-declared") // 経路の記録の無い古い操作も CLI とみなす
			if e.Via == federation.ViaAdmin {
				via = i18n.T("管理画面", "admin UI")
			}
			fmt.Printf("  %s  %-8s %-12s （%s） %s\n", e.At.Local().Format("2006-01-02 15:04"), e.Action, e.By, via, e.Detail)
		}
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSTATE\tDOMAINS\tEXPIRES\tFINGERPRINT")
	for _, p := range f.Partners {
		domains := p.Domains
		if len(domains) == 0 {
			domains = p.DeclaredDomains
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", p.ID, p.State, strings.Join(domains, ","), fmtTime(p.Expires), p.RootSHA256[:23]+"…")
	}
	return w.Flush()
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

// rootAnnounce はルート CA の入れ替えの予告を作る（オフラインの端末で、古いルート CA の鍵を使う）。
// 古いルートの鍵の侵害が理由の入れ替えには使わない（連携先には停止と、初回と同じ連携のやり直しを頼む）。
func rootAnnounce(args []string) error {
	fs := newFlags("root announce")
	oldCert := fs.String("old-root-cert", "", i18n.T("いまのルート CA の証明書", "current root CA certificate"))
	oldKey := fs.String("old-root-key", "", i18n.T("いまのルート CA の鍵", "current root CA key"))
	newCert := fs.String("new-root-cert", "", i18n.T("新しいルート CA の証明書", "new root CA certificate"))
	var domains []string
	fs.Var(listFlag{&domains}, "domains", i18n.T("新しいルートの範囲（連携先に申告している範囲を超えない）", "scope of the new root (must not exceed the scope declared to partners)"))
	var validity time.Duration = 90 * 24 * time.Hour
	fs.Var(durationFlag{&validity}, "validity", i18n.T("予告の有効期限（既定 90d、最大 180d）", "announcement expiry (default 90d, at most 180d)"))
	switchAt := fs.String("switch-at", "", i18n.T("新しいルートでの発行に切り替える予定日（YYYY-MM-DD）", "planned date to start issuing under the new root (YYYY-MM-DD)"))
	out := fs.String("out", "", i18n.T("書き出すファイル", "output file"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("old-root-cert", *oldCert, "old-root-key", *oldKey, "new-root-cert", *newCert, "out", *out); err != nil {
		return err
	}
	if len(domains) == 0 {
		return errors.New(i18n.T("-domains は必須", "-domains is required"))
	}
	var at time.Time
	if *switchAt != "" {
		var err error
		if at, err = time.Parse("2006-01-02", *switchAt); err != nil {
			return fmt.Errorf("-switch-at: %w", err)
		}
	}
	oldRoot, err := pki.LoadCert(*oldCert)
	if err != nil {
		return err
	}
	key, err := pki.LoadPrivateKey(*oldKey)
	if err != nil {
		return err
	}
	newRoot, err := pki.LoadCert(*newCert)
	if err != nil {
		return err
	}
	a, err := federation.NewAnnouncement(oldRoot, newRoot, domains, at, validity, time.Now())
	if err != nil {
		return err
	}
	compact, err := federation.SignAnnouncement(a, oldRoot, key)
	if err != nil {
		return err
	}
	if err := pki.WriteFileAtomic(*out, []byte(compact+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf(i18n.T("ルート CA の入れ替えの予告を書き出した（秘密情報は含まない）。\n  新しいルートの指紋: %s\n  範囲:               %v\n  予告の有効期限:     %s\n連携先に渡す。連携先は、いま信頼している古いルートで署名を確かめて取り込む（指紋の照合は不要）。\n", "exported the root CA rotation announcement (it contains no secrets).\n  New root fingerprint:   %s\n  Scope:                  %v\n  Announcement expires:   %s\nGive it to your partners. They verify its signature with the old root they currently trust and import it (no fingerprint comparison needed).\n"),
		a.NewRootSHA256, a.Domains, a.Expires.Local().Format(time.RFC3339))
	return nil
}

func fedAnnounce(args []string) error {
	fs := newFlags("federation announce")
	configPath := fs.String("config", "", i18n.T("mtls-ca の設定ファイル", "mtls-ca configuration file"))
	id := fs.String("id", "", i18n.T("連携先の識別子", "partner identifier"))
	in := fs.String("in", "", i18n.T("連携先から受け取った予告のファイル", "announcement file received from the partner"))
	by := fs.String("by", "", i18n.T("操作する管理者の名前", "name of the operating administrator"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("id", *id, "in", *in); err != nil {
		return err
	}
	env, err := loadFedEnv(*configPath)
	if err != nil {
		return err
	}
	who, err := operator(*by)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var p federation.Partner
	if err := federation.Update(env.file, func(f *federation.File) error {
		if err := f.ImportAnnouncement(*id, strings.TrimSpace(string(data)), env.roots, federation.ByCLI(who), time.Now()); err != nil {
			return err
		}
		p = *f.Find(*id)
		return nil
	}); err != nil {
		return err
	}
	fmt.Printf(i18n.T("連携先 %s のルート CA の入れ替えの予告を取り込んだ（署名は、いま信頼しているルートで確かめた）。\n  次のルートの指紋: %s\n  切り替えの予定日: %s\n承認すると新旧の両方を信頼する: mtlsctl federation approve-next -config ... -id %s\n", "imported the root CA rotation announcement for partner %s (signature verified with the currently trusted root).\n  Next root fingerprint: %s\n  Planned switch:        %s\nApprove it to trust both the old and new roots: mtlsctl federation approve-next -config ... -id %s\n"), *id, p.NextRootSHA256, fmtTime(p.NextSwitchAt), *id)
	return nil
}

// fedNext は approve-next / retire-root / cancel-next（どれも 1 人でできる）。
func fedNext(action string, args []string) error {
	fs := newFlags("federation " + action)
	configPath := fs.String("config", "", i18n.T("mtls-ca の設定ファイル", "mtls-ca configuration file"))
	id := fs.String("id", "", i18n.T("連携先の識別子", "partner identifier"))
	by := fs.String("by", "", i18n.T("操作する管理者の名前", "name of the operating administrator"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("id", *id); err != nil {
		return err
	}
	env, err := loadFedEnv(*configPath)
	if err != nil {
		return err
	}
	who, err := operator(*by)
	if err != nil {
		return err
	}
	actor, now := federation.ByCLI(who), time.Now()
	if err := federation.Update(env.file, func(f *federation.File) error {
		switch action {
		case "approve-next":
			return f.ApproveNext(*id, actor, now)
		case "retire-root":
			return f.RetireRoot(*id, actor, now)
		default:
			return f.CancelNext(*id, actor, now)
		}
	}); err != nil {
		return err
	}
	msg := map[string]string{
		"approve-next": i18n.T("次のルートを承認した。新旧の両方のルートを同じ範囲で信頼する（各サーバには既定 1 分以内に届く）", "approved the next root; both the old and new roots are trusted with the same scope (servers receive it within 1 minute by default)"),
		"retire-root":  i18n.T("古いルートを外し、次のルートを今のルートにした", "removed the old root and made the next root the current one"),
		"cancel-next":  i18n.T("次のルートを取り消した", "cancelled the next root"),
	}[action]
	fmt.Printf(i18n.T("連携先 %s: %s\n", "partner %s: %s\n"), *id, msg)
	return nil
}
