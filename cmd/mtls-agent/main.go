// mtls-agent は各サーバに常駐し、mtls-ca から証明書を取得して期限の前に自動で更新する。
//
//	mtls-agent run   -config /etc/mtls-agent/config.yaml   常駐して更新を続ける（SIGHUP ですぐ更新）
//	mtls-agent renew -config ... [-force]                  1 回だけ確認・更新して終了
//	mtls-agent check -config ...                           現在の証明書の状態を表示
//	mtls-agent version
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nobumin/mtls_manager/internal/agent"
	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/i18n"
	"github.com/nobumin/mtls_manager/internal/version"
)

// usage は使い方の表示。
func usage() string {
	return i18n.T(`使い方:
  mtls-agent run   -config FILE           常駐して証明書を自動更新する（SIGHUP ですぐ更新）
  mtls-agent renew -config FILE [-force]  1 回だけ確認し、必要なら更新して終了する
  mtls-agent check -config FILE           現在の証明書と連携版の状態を表示する（問題があれば終了コード 1）
  mtls-agent version
`, `Usage:
  mtls-agent run   -config FILE           run in the background and renew certificates automatically (SIGHUP renews now)
  mtls-agent renew -config FILE [-force]  check once, renew if needed, and exit
  mtls-agent check -config FILE           show the current certificate and federation status (exit code 1 on problems)
  mtls-agent version
`)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage())
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "version" || cmd == "-version" || cmd == "--version" {
		fmt.Println("mtls-agent", version.Version)
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configPath := fs.String("config", "/etc/mtls-agent/config.yaml", i18n.T("設定ファイル", "configuration file"))
	force := fs.Bool("force", false, i18n.T("renew: 更新時期を問わず取得する", "renew: obtain a certificate regardless of the renewal time"))
	_ = fs.Parse(args)

	var err error
	switch cmd {
	case "run":
		err = run(*configPath)
	case "renew":
		err = renew(*configPath, *force)
	case "check":
		err = check(*configPath)
	default:
		fmt.Fprint(os.Stderr, usage())
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mtls-agent:", err)
		os.Exit(1)
	}
}

func load(path string) (*config.Agent, *agent.Agent, error) {
	cfg, err := config.LoadAgent(path)
	if err != nil {
		return nil, nil, err
	}
	if w := i18n.InvalidEnvWarning(); w != "" {
		cfg.Log.NewLogger(os.Stderr).Warn(w)
	}
	a, err := agent.New(cfg, cfg.Log.NewLogger(os.Stderr))
	if err != nil {
		return nil, nil, err
	}
	return cfg, a, nil
}

func run(path string) error {
	cfg, a, err := load(path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	renewNow := make(chan struct{}, 1)
	go func() {
		for range hup {
			select {
			case renewNow <- struct{}{}:
			default:
			}
		}
	}()
	cfg.Log.NewLogger(os.Stderr).Info(i18n.T("mtls-agent を起動した", "mtls-agent started"), "version", version.Version, "names", cfg.Names, "ca", cfg.CAURL, "challenge", cfg.Challenge.Type)
	a.Run(ctx, renewNow)
	return nil
}

func renew(path string, force bool) error {
	_, a, err := load(path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st := a.Check(time.Now())
	if !st.NeedsRenewal() && !force {
		fmt.Printf(i18n.T("更新は不要（更新予定 %s、有効期限 %s）\n", "no renewal needed (planned renewal %s, expires %s)\n"), st.RenewAt.Local().Format(time.RFC3339), st.NotAfter.Local().Format(time.RFC3339))
	} else if err := a.Obtain(ctx); err != nil {
		return err
	}
	return a.SyncBundle(ctx, time.Now())
}

func check(path string) error {
	_, a, err := load(path)
	if err != nil {
		return err
	}
	now := time.Now()
	st := a.Check(now)
	bad := false
	if st.Exists {
		fmt.Printf(i18n.T("名前:       %v\nシリアル:   %s\n有効期限:   %s\n更新予定:   %s\n", "Names:       %v\nSerial:      %s\nExpires:     %s\nRenewal at:  %s\n"),
			st.Names, st.Serial, st.NotAfter.Local().Format(time.RFC3339), st.RenewAt.Local().Format(time.RFC3339))
	}
	if st.NeedsRenewal() {
		fmt.Println(i18n.T("状態:       更新が必要 –", "Status:      renewal needed –"), st.Reason)
		bad = true
	} else {
		fmt.Println(i18n.T("状態:       正常", "Status:      OK"))
	}
	if a.Config().FederationEnabled() {
		fmt.Println(i18n.T("連携版:    ", "Federation: "), a.BundleSummary())
		if p := a.BundleProblem(now); p != "" {
			fmt.Println(i18n.T("連携の状態: 問題あり –", "Federation status: problem –"), p)
			bad = true
		} else {
			fmt.Println(i18n.T("連携の状態: 正常", "Federation status: OK"))
		}
	}
	if bad {
		os.Exit(1)
	}
	return nil
}
