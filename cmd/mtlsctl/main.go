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
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/version"
)

const usage = `使い方:
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
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, errUsage) {
			fmt.Fprint(os.Stderr, usage)
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
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	return fs
}

func required(pairs ...string) error {
	for i := 0; i < len(pairs); i += 2 {
		if pairs[i+1] == "" {
			return fmt.Errorf("-%s は必須", pairs[i])
		}
	}
	return nil
}

func rootCreate(args []string) error {
	fs := newFlags("root create")
	outDir := fs.String("out-dir", "", "出力先ディレクトリ（root.key / root.crt を作る）")
	cn := fs.String("cn", "", "ルート CA の名前（例: Example Internal Root CA）")
	org := fs.String("org", "", "組織名")
	keyType := fs.String("key-type", pki.KeyECDSAP384, "鍵の種類")
	validity := 10 * 365 * 24 * time.Hour
	fs.Var(durationFlag{&validity}, "validity", "有効期間（例: 10y）")
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
		return fmt.Errorf("%s はすでに存在する（上書きしない）", certPath)
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
	fmt.Printf("ルート CA を作成した\n  秘密鍵: %s（オフラインで保管する。CA サーバには置かない）\n  証明書: %s（各サーバに配る）\n  有効期限: %s\n",
		keyPath, certPath, cert.NotAfter.Local().Format(time.RFC3339))
	return nil
}

func intermediateCSR(args []string) error {
	fs := newFlags("intermediate csr")
	outDir := fs.String("out-dir", "", "出力先ディレクトリ（intermediate.key / intermediate.csr を作る）")
	cn := fs.String("cn", "", "中間 CA の名前（例: Example Internal mTLS CA 2026）")
	org := fs.String("org", "", "組織名")
	keyType := fs.String("key-type", pki.KeyECDSAP256, "鍵の種類")
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
	fmt.Printf("中間 CA の鍵と CSR を作成した\n  秘密鍵: %s（CA サーバから出さない）\n  CSR:    %s（ルート CA の端末へ運び、intermediate sign で署名する）\n", keyPath, csrPath)
	return nil
}

func intermediateSign(args []string) error {
	fs := newFlags("intermediate sign")
	rootCert := fs.String("root-cert", "", "ルート CA の証明書")
	rootKey := fs.String("root-key", "", "ルート CA の秘密鍵")
	csrPath := fs.String("csr", "", "中間 CA の CSR")
	out := fs.String("out", "", "出力する中間 CA の証明書")
	var permitted []string
	fs.Var(listFlag{&permitted}, "permitted-domain", "発行できるドメイン（名前制約。カンマ区切り・複数指定可）")
	noConstraints := fs.Bool("no-name-constraints", false, "名前制約を付けない（非推奨）")
	validity := 2 * 365 * 24 * time.Hour
	fs.Var(durationFlag{&validity}, "validity", "有効期間（例: 2y）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("root-cert", *rootCert, "root-key", *rootKey, "csr", *csrPath, "out", *out); err != nil {
		return err
	}
	if len(permitted) == 0 && !*noConstraints {
		return errors.New("-permitted-domain で発行できるドメインを指定する（付けない場合は -no-name-constraints）")
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
	fmt.Printf("中間 CA の証明書を作成した\n  証明書:   %s（CA サーバへ運ぶ）\n  名前制約: %v\n  有効期限: %s\n", *out, cert.PermittedDNSDomains, cert.NotAfter.Local().Format(time.RFC3339))
	return nil
}

func eabCreate(args []string) error {
	fs := newFlags("eab create")
	file := fs.String("file", "", "EAB 鍵ファイル（CA の eab_file。無ければ作る）")
	var patterns []string
	fs.Var(listFlag{&patterns}, "names", "この鍵で発行してよい名前（例: web1.internal.example.com, *.batch.internal.example.com）")
	note := fs.String("note", "", "メモ（ホスト名・担当など）")
	hmacOut := fs.String("hmac-out", "", "HMAC 鍵を書き出すファイル（0600。省略時は画面に表示）")
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
	fmt.Printf("EAB 鍵を作成した\n  kid:   %s\n  names: %v\n", k.KID, k.Names)
	if *hmacOut != "" {
		fmt.Printf("  hmac:  %s に書き出した（対象のサーバへ安全な経路で運び、mtls-agent の eab.hmac_file に指定する）\n", *hmacOut)
	} else {
		fmt.Printf("  hmac:  %s\n（この値は秘密情報。対象のサーバの mtls-agent にだけ渡す）\n", k.HMAC)
	}
	return nil
}

func eabList(args []string) error {
	fs := newFlags("eab list")
	file := fs.String("file", "", "EAB 鍵ファイル")
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
	file := fs.String("file", "", "EAB 鍵ファイル")
	kid := fs.String("kid", "", "取り消す鍵の kid")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required("file", *file, "kid", *kid); err != nil {
		return err
	}
	if err := eab.Update(*file, func(f *eab.File) error {
		if !f.Remove(*kid) {
			return fmt.Errorf("kid %s が見つからない", *kid)
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Printf("EAB 鍵 %s を取り消した。この鍵で登録したサーバは、以後新しい証明書を取得できない\n（発行済みの証明書は有効期限まで使える。すぐに止めるには失効させる）\n", *kid)
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
		fmt.Printf("[%d] Subject:   %s\n    Issuer:    %s\n    Serial:    %x\n    有効期間:  %s 〜 %s\n",
			i, c.Subject, c.Issuer, c.SerialNumber, c.NotBefore.Local().Format(time.RFC3339), c.NotAfter.Local().Format(time.RFC3339))
		if c.IsCA {
			fmt.Printf("    CA:        はい（MaxPathLen=%d）\n", c.MaxPathLen)
			if len(c.PermittedDNSDomains) > 0 {
				fmt.Printf("    名前制約:  %v\n", c.PermittedDNSDomains)
			}
		}
		if len(c.DNSNames) > 0 {
			fmt.Printf("    DNS 名:    %v\n", c.DNSNames)
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
			fmt.Printf("    用途:      %s\n", strings.Join(usages, ", "))
		}
	}
	return nil
}
