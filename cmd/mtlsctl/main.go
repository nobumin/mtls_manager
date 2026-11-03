// mtlsctl は CA の鍵・証明書と EAB 鍵、連携版の連携先を管理するコマンド。
package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/eab"
	"github.com/nobumin/mtls_manager/internal/i18n"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/version"
)

// usage は使い方の表示。
func usage() string {
	return i18n.T(`使い方:
  ルート CA（オフラインの端末で実行する）
    mtlsctl root create -out-dir DIR -cn NAME [-org ORG] [-key-type ecdsa-p384] [-validity 10y]
    mtlsctl root announce -old-root-cert F -old-root-key F -new-root-cert F -domains D[,D..] -out F [-switch-at YYYY-MM-DD] [-validity 90d]
                                   （連携版: ルート CA の入れ替えの予告。古いルートの鍵の侵害時は使わない）

  中間 CA
    mtlsctl intermediate csr  -out-dir DIR -cn NAME [-org ORG] [-key-type ecdsa-p256]     （CA サーバで実行）
    mtlsctl intermediate sign -root-cert FILE -root-key FILE -csr FILE -out FILE \
                              -permitted-domain internal.example.com [-validity 2y]       （オフラインの端末で実行）

  EAB 鍵（ホストごとの発行許可）
    mtlsctl eab create -file FILE -names web1.internal.example.com[,..] [-note TEXT] [-hmac-out FILE]
    mtlsctl eab list   -file FILE
    mtlsctl eab revoke -file FILE -kid KID

  連携版（別々の mtls-ca で管理するサーバ間の mTLS。-config は mtls-ca の設定ファイル）
    mtlsctl federation export  -config FILE [-org ORG] [-contacts ..] [-domains ..] [-out FILE]
    mtlsctl federation import  -config FILE -in FILE -id ID
    mtlsctl federation request -config FILE -id ID -compared-with TEXT [-fingerprint FP] [-domains ..] [-validity 1y]  （1 人目）
    mtlsctl federation approve -config FILE -id ID [-fingerprint FP]                                                  （別の管理者）
    mtlsctl federation suspend -config FILE -id ID [-reason TEXT]
    mtlsctl federation remove  -config FILE -id ID
    mtlsctl federation list    -config FILE [-id ID]
    mtlsctl federation announce     -config FILE -id ID -in FILE   （連携先のルート CA の入れ替えの予告を取り込む）
    mtlsctl federation approve-next -config FILE -id ID            （次のルートを承認する。1 人でよい）
    mtlsctl federation retire-root  -config FILE -id ID            （古いルートを外す）
    mtlsctl federation cancel-next  -config FILE -id ID
    （操作した管理者の名前は -by。省略時は SUDO_USER / USER）

  その他
    mtlsctl inspect FILE    証明書の内容を表示する
    mtlsctl version
`, `Usage:
  Root CA (run on the offline machine)
    mtlsctl root create -out-dir DIR -cn NAME [-org ORG] [-key-type ecdsa-p384] [-validity 10y]
    mtlsctl root announce -old-root-cert F -old-root-key F -new-root-cert F -domains D[,D..] -out F [-switch-at YYYY-MM-DD] [-validity 90d]
                                   (federation: root CA rotation announcement; do not use when the old root key is compromised)

  Intermediate CA
    mtlsctl intermediate csr  -out-dir DIR -cn NAME [-org ORG] [-key-type ecdsa-p256]     (run on the CA server)
    mtlsctl intermediate sign -root-cert FILE -root-key FILE -csr FILE -out FILE \
                              -permitted-domain internal.example.com [-validity 2y]       (run on the offline machine)

  EAB keys (per-host permission to obtain certificates)
    mtlsctl eab create -file FILE -names web1.internal.example.com[,..] [-note TEXT] [-hmac-out FILE]
    mtlsctl eab list   -file FILE
    mtlsctl eab revoke -file FILE -kid KID

  Federation (mTLS between servers managed by separate mtls-cas; -config is the mtls-ca configuration file)
    mtlsctl federation export  -config FILE [-org ORG] [-contacts ..] [-domains ..] [-out FILE]
    mtlsctl federation import  -config FILE -in FILE -id ID
    mtlsctl federation request -config FILE -id ID -compared-with TEXT [-fingerprint FP] [-domains ..] [-validity 1y]  (first administrator)
    mtlsctl federation approve -config FILE -id ID [-fingerprint FP]                                                  (another administrator)
    mtlsctl federation suspend -config FILE -id ID [-reason TEXT]
    mtlsctl federation remove  -config FILE -id ID
    mtlsctl federation list    -config FILE [-id ID]
    mtlsctl federation announce     -config FILE -id ID -in FILE   (import a partner's root CA rotation announcement)
    mtlsctl federation approve-next -config FILE -id ID            (approve the next root; one person is enough)
    mtlsctl federation retire-root  -config FILE -id ID            (remove the old root)
    mtlsctl federation cancel-next  -config FILE -id ID
    (the operating administrator's name is -by; defaults to SUDO_USER / USER)

  Other
    mtlsctl inspect FILE    show the contents of a certificate
    mtlsctl version
`)
}

func main() {
	if w := i18n.InvalidEnvWarning(); w != "" {
		fmt.Fprintln(os.Stderr, "mtlsctl:", w)
	}
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, errUsage) {
			fmt.Fprint(os.Stderr, usage())
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "mtlsctl:", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func run(args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	sub := func(n int) string {
		if len(args) > n {
			return args[n]
		}
		return ""
	}
	switch args[0] + " " + sub(1) {
	case "root create":
		return rootCreate(args[2:])
	case "intermediate csr":
		return intermediateCSR(args[2:])
	case "intermediate sign":
		return intermediateSign(args[2:])
	case "eab create":
		return eabCreate(args[2:])
	case "eab list":
		return eabList(args[2:])
	case "eab revoke":
		return eabRevoke(args[2:])
	case "federation export":
		return fedExport(args[2:])
	case "federation import":
		return fedImport(args[2:])
	case "federation request":
		return fedRequest(args[2:])
	case "federation approve":
		return fedApprove(args[2:])
	case "federation suspend":
		return fedSuspend(args[2:])
	case "federation remove":
		return fedRemove(args[2:])
	case "federation list":
		return fedList(args[2:])
	case "federation announce":
		return fedAnnounce(args[2:])
	case "federation approve-next", "federation retire-root", "federation cancel-next":
		return fedNext(args[1], args[2:])
	case "root announce":
		return rootAnnounce(args[2:])
	}
	switch args[0] {
	case "inspect":
		if len(args) != 2 {
			return errUsage
		}
		return inspect(args[1])
	case "version", "-version", "--version":
		fmt.Println("mtlsctl", version.Version)
		return nil
	}
	return errUsage
}

type durationFlag struct{ d *time.Duration }

func (f durationFlag) String() string {
	if f.d == nil {
		return ""
	}
	return f.d.String()
}

func (f durationFlag) Set(s string) error {
	d, err := config.ParseDuration(s)
	if err != nil {
		return err
	}
	*f.d = d
	return nil
}

type listFlag struct{ v *[]string }

func (f listFlag) String() string {
	if f.v == nil {
		return ""
	}
	return strings.Join(*f.v, ",")
}

func (f listFlag) Set(s string) error {
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*f.v = append(*f.v, p)
		}
	}
	return nil
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("mtlsctl "+name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage()) }
	return fs
}

func required(pairs ...string) error {
	for i := 0; i < len(pairs); i += 2 {
		if pairs[i+1] == "" {
			return fmt.Errorf(i18n.T("-%s は必須", "-%s is required"), pairs[i])
		}
	}
	return nil
}

func rootCreate(args []string) error {
	fs := newFlags("root create")
	outDir := fs.String("out-dir", "", i18n.T("出力先ディレクトリ（root.key / root.crt を作る）", "output directory (root.key / root.crt are created)"))
	cn := fs.String("cn", "", i18n.T("ルート CA の名前（例: Example Internal Root CA）", "root CA name (e.g. Example Internal Root CA)"))
	org := fs.String("org", "", i18n.T("組織名", "organization name"))
	keyType := fs.String("key-type", pki.KeyECDSAP384, i18n.T("鍵の種類", "key type"))
	validity := 10 * 365 * 24 * time.Hour
	fs.Var(durationFlag{&validity}, "validity", i18n.T("有効期間（例: 10y）", "validity (e.g. 10y)"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("out-dir", *outDir, "cn", *cn); err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return err
	}
	keyPath, certPath := filepath.Join(*outDir, "root.key"), filepath.Join(*outDir, "root.crt")
	if _, err := os.Stat(certPath); err == nil {
		return fmt.Errorf(i18n.T("%s はすでに存在する（上書きしない）", "%s already exists (not overwriting)"), certPath)
	}
	key, err := pki.GenerateKey(*keyType)
	if err != nil {
		return err
	}
	cert, err := pki.CreateRoot(key, pki.RootOptions{CommonName: *cn, Organization: *org, Validity: validity})
	if err != nil {
		return err
	}
	if err := pki.SavePrivateKey(keyPath, key); err != nil {
		return err
	}
	if err := pki.WriteNewFile(certPath, pki.EncodeCertsPEM(cert), 0o644); err != nil {
		return err
	}
	fmt.Printf(i18n.T("ルート CA を作成した\n  秘密鍵: %s（オフラインで保管する。CA サーバには置かない）\n  証明書: %s（各サーバに配る）\n  有効期限: %s\n", "created the root CA\n  Private key: %s (keep it offline; never put it on the CA server)\n  Certificate: %s (distribute it to every server)\n  Expires: %s\n"),
		keyPath, certPath, cert.NotAfter.Local().Format(time.RFC3339))
	return nil
}

func intermediateCSR(args []string) error {
	fs := newFlags("intermediate csr")
	outDir := fs.String("out-dir", "", i18n.T("出力先ディレクトリ（intermediate.key / intermediate.csr を作る）", "output directory (intermediate.key / intermediate.csr are created)"))
	cn := fs.String("cn", "", i18n.T("中間 CA の名前（例: Example Internal mTLS CA 2026）", "intermediate CA name (e.g. Example Internal mTLS CA 2026)"))
	org := fs.String("org", "", i18n.T("組織名", "organization name"))
	keyType := fs.String("key-type", pki.KeyECDSAP256, i18n.T("鍵の種類", "key type"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("out-dir", *outDir, "cn", *cn); err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return err
	}
	keyPath, csrPath := filepath.Join(*outDir, "intermediate.key"), filepath.Join(*outDir, "intermediate.csr")
	key, err := pki.GenerateKey(*keyType)
	if err != nil {
		return err
	}
	csr, err := pki.CreateCSR(key, *cn, *org)
	if err != nil {
		return err
	}
	if err := pki.SavePrivateKey(keyPath, key); err != nil {
		return err
	}
	if err := pki.WriteNewFile(csrPath, pki.EncodeCSRPEM(csr), 0o644); err != nil {
		return err
	}
	fmt.Printf(i18n.T("中間 CA の鍵と CSR を作成した\n  秘密鍵: %s（CA サーバから出さない）\n  CSR:    %s（ルート CA の端末へ運び、intermediate sign で署名する）\n", "created the intermediate CA key and CSR\n  Private key: %s (never take it off the CA server)\n  CSR:         %s (take it to the root CA machine and sign it with intermediate sign)\n"), keyPath, csrPath)
	return nil
}

func intermediateSign(args []string) error {
	fs := newFlags("intermediate sign")
	rootCert := fs.String("root-cert", "", i18n.T("ルート CA の証明書", "root CA certificate"))
	rootKey := fs.String("root-key", "", i18n.T("ルート CA の秘密鍵", "root CA private key"))
	csrPath := fs.String("csr", "", i18n.T("中間 CA の CSR", "intermediate CA CSR"))
	out := fs.String("out", "", i18n.T("出力する中間 CA の証明書", "intermediate CA certificate to write"))
	var permitted []string
	fs.Var(listFlag{&permitted}, "permitted-domain", i18n.T("発行できるドメイン（名前制約。カンマ区切り・複数指定可）", "domains that may be issued (name constraints; comma-separated, may be repeated)"))
	noConstraints := fs.Bool("no-name-constraints", false, i18n.T("名前制約を付けない（非推奨）", "do not add name constraints (not recommended)"))
	validity := 2 * 365 * 24 * time.Hour
	fs.Var(durationFlag{&validity}, "validity", i18n.T("有効期間（例: 2y）", "validity (e.g. 2y)"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("root-cert", *rootCert, "root-key", *rootKey, "csr", *csrPath, "out", *out); err != nil {
		return err
	}
	if len(permitted) == 0 && !*noConstraints {
		return errors.New(i18n.T("-permitted-domain で発行できるドメインを指定する（付けない場合は -no-name-constraints）", "specify the domains that may be issued with -permitted-domain (or -no-name-constraints to omit them)"))
	}
	root, err := pki.LoadCert(*rootCert)
	if err != nil {
		return err
	}
	key, err := pki.LoadPrivateKey(*rootKey)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*csrPath)
	if err != nil {
		return err
	}
	csr, err := pki.ParseCSRPEM(data)
	if err != nil {
		return err
	}
	cert, err := pki.SignIntermediate(root, key, csr, pki.IntermediateOptions{Validity: validity, PermittedDomains: permitted})
	if err != nil {
		return err
	}
	if err := pki.WriteNewFile(*out, pki.EncodeCertsPEM(cert), 0o644); err != nil {
		return err
	}
	fmt.Printf(i18n.T("中間 CA の証明書を作成した\n  証明書:   %s（CA サーバへ運ぶ）\n  名前制約: %v\n  有効期限: %s\n", "created the intermediate CA certificate\n  Certificate:      %s (take it to the CA server)\n  Name constraints: %v\n  Expires:          %s\n"), *out, cert.PermittedDNSDomains, cert.NotAfter.Local().Format(time.RFC3339))
	return nil
}

func eabCreate(args []string) error {
	fs := newFlags("eab create")
	file := fs.String("file", "", i18n.T("EAB 鍵ファイル（CA の eab_file。無ければ作る）", "EAB key file (the CA's eab_file; created if missing)"))
	var patterns []string
	fs.Var(listFlag{&patterns}, "names", i18n.T("この鍵で発行してよい名前（例: web1.internal.example.com, *.batch.internal.example.com）", "names this key may obtain (e.g. web1.internal.example.com, *.batch.internal.example.com)"))
	note := fs.String("note", "", i18n.T("メモ（ホスト名・担当など）", "note (host name, owner, etc.)"))
	hmacOut := fs.String("hmac-out", "", i18n.T("HMAC 鍵を書き出すファイル（0600。省略時は画面に表示）", "file to write the HMAC key to (0600; shown on screen if omitted)"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("file", *file); err != nil {
		return err
	}
	// 同時に実行された create / revoke の変更を失わないよう、ロックの下で読み書きする。
	var k eab.Key
	if err := eab.Update(*file, func(f *eab.File) error {
		var err error
		if k, err = f.Add(patterns, *note); err != nil {
			return err
		}
		if *hmacOut != "" {
			return pki.WriteNewFile(*hmacOut, []byte(k.HMAC+"\n"), 0o600)
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Printf(i18n.T("EAB 鍵を作成した\n  kid:   %s\n  names: %v\n", "created an EAB key\n  kid:   %s\n  names: %v\n"), k.KID, k.Names)
	if *hmacOut != "" {
		fmt.Printf(i18n.T("  hmac:  %s に書き出した（対象のサーバへ安全な経路で運び、mtls-agent の eab.hmac_file に指定する）\n", "  hmac:  written to %s (take it to the target server over a secure channel and set it as mtls-agent's eab.hmac_file)\n"), *hmacOut)
	} else {
		fmt.Printf(i18n.T("  hmac:  %s\n（この値は秘密情報。対象のサーバの mtls-agent にだけ渡す）\n", "  hmac:  %s\n(this value is a secret; give it only to the target server's mtls-agent)\n"), k.HMAC)
	}
	return nil
}

func eabList(args []string) error {
	fs := newFlags("eab list")
	file := fs.String("file", "", i18n.T("EAB 鍵ファイル", "EAB key file"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("file", *file); err != nil {
		return err
	}
	f, err := eab.Load(*file)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "KID\tNAMES\tCREATED\tNOTE")
	keys := slices.Clone(f.Keys)
	slices.SortFunc(keys, func(a, b eab.Key) int { return a.CreatedAt.Compare(b.CreatedAt) })
	for _, k := range keys {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", k.KID, strings.Join(k.Names, ","), k.CreatedAt.Local().Format("2006-01-02 15:04"), k.Note)
	}
	return w.Flush()
}

func eabRevoke(args []string) error {
	fs := newFlags("eab revoke")
	file := fs.String("file", "", i18n.T("EAB 鍵ファイル", "EAB key file"))
	kid := fs.String("kid", "", i18n.T("取り消す鍵の kid", "kid of the key to revoke"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("file", *file, "kid", *kid); err != nil {
		return err
	}
	if err := eab.Update(*file, func(f *eab.File) error {
		if !f.Remove(*kid) {
			return fmt.Errorf(i18n.T("kid %s が見つからない", "kid %s not found"), *kid)
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Printf(i18n.T("EAB 鍵 %s を取り消した。この鍵で登録したサーバは、以後新しい証明書を取得できない\n（発行済みの証明書は有効期限まで使える。すぐに止めるには失効させる）\n", "revoked EAB key %s. Servers registered with this key can no longer obtain new certificates\n(certificates already issued remain usable until they expire; revoke them to stop them immediately)\n"), *kid)
	return nil
}

func inspect(path string) error {
	certs, err := pki.LoadCerts(path)
	if err != nil {
		return err
	}
	for i, c := range certs {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf(i18n.T("[%d] Subject:   %s\n    Issuer:    %s\n    Serial:    %x\n    有効期間:  %s 〜 %s\n", "[%d] Subject:   %s\n    Issuer:    %s\n    Serial:    %x\n    Validity:  %s to %s\n"),
			i, c.Subject, c.Issuer, c.SerialNumber, c.NotBefore.Local().Format(time.RFC3339), c.NotAfter.Local().Format(time.RFC3339))
		if c.IsCA {
			fmt.Printf(i18n.T("    CA:        はい（MaxPathLen=%d）\n", "    CA:        yes (MaxPathLen=%d)\n"), c.MaxPathLen)
			if len(c.PermittedDNSDomains) > 0 {
				fmt.Printf(i18n.T("    名前制約:  %v\n", "    Permitted: %v\n"), c.PermittedDNSDomains)
			}
		}
		if len(c.DNSNames) > 0 {
			fmt.Printf(i18n.T("    DNS 名:    %v\n", "    DNS names: %v\n"), c.DNSNames)
		}
		var usages []string
		for _, u := range c.ExtKeyUsage {
			switch u {
			case x509.ExtKeyUsageServerAuth:
				usages = append(usages, "serverAuth")
			case x509.ExtKeyUsageClientAuth:
				usages = append(usages, "clientAuth")
			default:
				usages = append(usages, fmt.Sprint(u))
			}
		}
		if len(usages) > 0 {
			fmt.Printf(i18n.T("    用途:      %s\n", "    Usage:     %s\n"), strings.Join(usages, ", "))
		}
	}
	return nil
}
