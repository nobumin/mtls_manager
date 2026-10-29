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
	"github.com/nobumin/mtls_manager/internal/version"
)

const usage = `使い方:
  mtls-agent run   -config FILE           常駐して証明書を自動更新する（SIGHUP ですぐ更新）
  mtls-agent renew -config FILE [-force]  1 回だけ確認し、必要なら更新して終了する
  mtls-agent check -config FILE           現在の証明書の状態を表示する（更新が必要なら終了コード 1）
  mtls-agent version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "version" || cmd == "-version" || cmd == "--version" {
		fmt.Println("mtls-agent", version.Version)
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configPath := fs.String("config", "/etc/mtls-agent/config.yaml", "設定ファイル")
	force := fs.Bool("force", false, "renew: 更新時期を問わず取得する")
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
		fmt.Fprint(os.Stderr, usage)
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
	cfg.Log.NewLogger(os.Stderr).Info("mtls-agent を起動した", "version", version.Version, "names", cfg.Names, "ca", cfg.CAURL, "challenge", cfg.Challenge.Type)
	a.Run(ctx, renewNow)
	return nil
}

func renew(path string, force bool) error {
	_, a, err := load(path)
	if err != nil {
		return err
	}
	st := a.Check(time.Now())
	if !st.NeedsRenewal() && !force {
		fmt.Printf("更新は不要（更新予定 %s、有効期限 %s）\n", st.RenewAt.Local().Format(time.RFC3339), st.NotAfter.Local().Format(time.RFC3339))
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.Obtain(ctx)
}

func check(path string) error {
	_, a, err := load(path)
	if err != nil {
		return err
	}
	st := a.Check(time.Now())
	if st.Exists {
		fmt.Printf("名前:       %v\nシリアル:   %s\n有効期限:   %s\n更新予定:   %s\n",
			st.Names, st.Serial, st.NotAfter.Local().Format(time.RFC3339), st.RenewAt.Local().Format(time.RFC3339))
	}
	if st.NeedsRenewal() {
		fmt.Println("状態:       更新が必要 –", st.Reason)
		os.Exit(1)
	}
	fmt.Println("状態:       正常")
	return nil
}
