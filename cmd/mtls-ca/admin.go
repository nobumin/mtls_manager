package main

import (
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/i18n"
	"github.com/nobumin/mtls_manager/internal/store"
)

// 管理用のサブコマンドはデータベースを直接開く。データベースは mtls-ca の起動中はロックされている
// （開けなければ store.Open が「別の mtls-ca が動いていないか」を示すエラーを返す）ので、
// 実行前に mtls-ca を止める（数秒で済む）。

func openDB(args []string, name string, extra func(*flag.FlagSet)) (*store.DB, error) {
	fs := flag.NewFlagSet("mtls-ca "+name, flag.ExitOnError)
	configPath := fs.String("config", "/etc/mtls-ca/config.yaml", i18n.T("設定ファイル", "configuration file"))
	if extra != nil {
		extra(fs)
	}
	_ = fs.Parse(args)
	cfg, err := config.LoadCA(*configPath)
	if err != nil {
		return nil, err
	}
	db, err := store.Open(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func listCerts(args []string) error {
	var all bool
	db, err := openDB(args, "certs", func(fs *flag.FlagSet) {
		fs.BoolVar(&all, "all", false, i18n.T("期限切れも表示する", "also show expired certificates"))
	})
	if err != nil {
		return err
	}
	defer db.Close()
	certs, err := db.Certs()
	if err != nil {
		return err
	}
	slices.SortFunc(certs, func(a, b store.Cert) int { return a.NotBefore.Compare(b.NotBefore) })
	now := time.Now()
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SERIAL\tNAMES\tNOT_AFTER\tSTATUS")
	for _, c := range certs {
		status := i18n.T("有効", "valid")
		switch {
		case c.Pending && !c.Revoked:
			// 署名の前に記録したまま完了しなかったもの。外に出ていない可能性が高いが、必要なら失効できる。
			status = i18n.T("未完了", "incomplete")
		case c.Revoked:
			status = i18n.T("失効 ", "revoked ") + c.RevokedAt.Local().Format("2006-01-02 15:04")
		case !now.Before(c.NotAfter):
			if !all {
				continue
			}
			status = i18n.T("期限切れ", "expired")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.Serial, strings.Join(c.Names, ","), c.NotAfter.Local().Format("2006-01-02 15:04"), status)
	}
	return w.Flush()
}

func revokeCert(args []string) error {
	var serial string
	var reason int
	db, err := openDB(args, "revoke", func(fs *flag.FlagSet) {
		fs.StringVar(&serial, "serial", "", i18n.T("失効させる証明書のシリアル（16 進。mtls-ca certs で確認）", "serial of the certificate to revoke (hex; see mtls-ca certs)"))
		fs.IntVar(&reason, "reason", 0, i18n.T("失効理由（0: 指定なし, 1: 鍵の漏えい, 3: 所属の変更, 4: 置き換え, 5: 運用停止）", "revocation reason (0: unspecified, 1: key compromise, 3: affiliation changed, 4: superseded, 5: cessation of operation)"))
	})
	if err != nil {
		return err
	}
	defer db.Close()
	if serial == "" {
		return errors.New(i18n.T("-serial は必須", "-serial is required"))
	}
	// openssl の表示（コロン区切り・先頭の 0）でも受け付けるよう、数値として読み直して保存時の書式にそろえる。
	n, ok := new(big.Int).SetString(strings.TrimPrefix(strings.ReplaceAll(strings.ToLower(serial), ":", ""), "0x"), 16)
	if !ok {
		return fmt.Errorf(i18n.T("シリアル %q を 16 進として解釈できない", "cannot parse serial %q as hex"), serial)
	}
	serial = fmt.Sprintf("%x", n)
	err = db.RevokeCert(serial, reason, nil)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf(i18n.T("シリアル %s の証明書が見つからない", "no certificate with serial %s"), serial)
	}
	if err != nil {
		return err
	}
	fmt.Printf(i18n.T("証明書 %s を失効させた。mtls-ca を起動すると CRL に反映される\n", "revoked certificate %s; it appears in the CRL when mtls-ca starts\n"), serial)
	return nil
}
