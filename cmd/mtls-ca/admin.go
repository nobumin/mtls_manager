package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/store"
)

// 管理用のサブコマンドはデータベースを直接開く。データベースは mtls-ca の起動中はロックされている
// （開けなければ store.Open が「別の mtls-ca が動いていないか」を示すエラーを返す）ので、
// 実行前に mtls-ca を止める（数秒で済む）。

func openDB(args []string, name string, extra func(*flag.FlagSet)) (*store.DB, error) {
	fs := flag.NewFlagSet("mtls-ca "+name, flag.ExitOnError)
	configPath := fs.String("config", "/etc/mtls-ca/config.yaml", "設定ファイル")
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
		fs.BoolVar(&all, "all", false, "期限切れも表示する")
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
		status := "有効"
		switch {
		case c.Revoked:
			status = "失効 " + c.RevokedAt.Local().Format("2006-01-02 15:04")
		case !now.Before(c.NotAfter):
			if !all {
				continue
			}
			status = "期限切れ"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.Serial, strings.Join(c.Names, ","), c.NotAfter.Local().Format("2006-01-02 15:04"), status)
	}
	return w.Flush()
}

func revokeCert(args []string) error {
	var serial string
	var reason int
	db, err := openDB(args, "revoke", func(fs *flag.FlagSet) {
		fs.StringVar(&serial, "serial", "", "失効させる証明書のシリアル（16 進。mtls-ca certs で確認）")
		fs.IntVar(&reason, "reason", 0, "失効理由（0: 指定なし, 1: 鍵の漏えい, 3: 所属の変更, 4: 置き換え, 5: 運用停止）")
	})
	if err != nil {
		return err
	}
	defer db.Close()
	if serial == "" {
		return errors.New("-serial は必須")
	}
	if !slices.Contains([]int{0, 1, 3, 4, 5}, reason) {
		return fmt.Errorf("失効理由 %d は指定できない", reason)
	}
	serial = strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(serial, ":", ""), "0x"))
	_, err = db.UpdateCert(serial, func(c *store.Cert) error {
		if c.Revoked {
			return errors.New("すでに失効している")
		}
		c.Revoked, c.RevokedAt, c.Reason = true, time.Now().UTC(), reason
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("シリアル %s の証明書が見つからない", serial)
	}
	if err != nil {
		return err
	}
	fmt.Printf("証明書 %s を失効させた。mtls-ca を起動すると CRL に反映される\n", serial)
	return nil
}
