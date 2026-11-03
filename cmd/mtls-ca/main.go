// mtls-ca は mTLS 用の証明書を発行するプライベート CA（ACME サーバ）。
//
//	mtls-ca -config /etc/mtls-ca/config.yaml                 CA を起動する
//	mtls-ca certs  -config ... [-all]                        発行済みの証明書を一覧する（CA を止めて実行）
//	mtls-ca revoke -config ... -serial HEX [-reason N]       証明書を失効させる（CA を止めて実行）
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nobumin/mtls_manager/internal/acmeserver"
	"github.com/nobumin/mtls_manager/internal/admin"
	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/eab"
	"github.com/nobumin/mtls_manager/internal/federation"
	"github.com/nobumin/mtls_manager/internal/i18n"
	"github.com/nobumin/mtls_manager/internal/logbuf"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/store"
	"github.com/nobumin/mtls_manager/internal/version"
)

var adminCommands = map[string]func([]string) error{
	"certs":  listCerts,
	"revoke": revokeCert,
}

func main() {
	if len(os.Args) > 1 {
		if cmd, ok := adminCommands[os.Args[1]]; ok {
			if err := cmd(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "mtls-ca:", err)
				os.Exit(1)
			}
			return
		}
	}
	configPath := flag.String("config", "/etc/mtls-ca/config.yaml", i18n.T("設定ファイル", "configuration file"))
	showVersion := flag.Bool("version", false, i18n.T("バージョンを表示して終了", "print the version and exit"))
	flag.Parse()
	if *showVersion {
		fmt.Println("mtls-ca", version.Version)
		return
	}
	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "mtls-ca:", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.LoadCA(configPath)
	if err != nil {
		return err
	}
	// 管理画面でログを閲覧できるよう、直近のログをメモリにも残す（管理画面が無効なら残さない）。
	started := time.Now()
	var logs *logbuf.Buffer
	handler := cfg.Log.NewHandler(os.Stderr)
	if cfg.Admin.Listen != "" {
		logs = logbuf.New(cfg.Admin.LogBuffer)
		handler = logs.Handler(handler)
	}
	log := slog.New(handler)
	if w := i18n.InvalidEnvWarning(); w != "" {
		log.Warn(w)
	}

	iss, err := pki.LoadIssuer(cfg.IntermediateCert, cfg.IntermediateKey, cfg.RootCert)
	if err != nil {
		return err
	}
	if len(iss.Cert.PermittedDNSDomains) == 0 {
		log.Warn(i18n.T("中間 CA に名前制約がない。mtlsctl intermediate sign -permitted-domain で作り直すことを推奨する", "the intermediate CA has no name constraints; recreating it with mtlsctl intermediate sign -permitted-domain is recommended"))
	}
	for _, d := range cfg.Policy.AllowedDomains {
		if !iss.Permits(d) {
			return fmt.Errorf(i18n.T("policy.allowed_domains の %q が中間 CA の名前制約 %v の範囲外", "%q in policy.allowed_domains is outside the intermediate CA's name constraints %v"), d, iss.Cert.PermittedDNSDomains)
		}
	}
	if len(cfg.AllowedClientCIDRs) == 0 {
		log.Warn(i18n.T("allowed_client_cidrs が空のため、どこからでも CA に接続できる", "allowed_client_cidrs is empty, so the CA accepts connections from anywhere"))
	}

	db, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()
	eabStore, err := eab.NewStore(cfg.EABFile)
	if err != nil {
		return fmt.Errorf(i18n.T("eab_file: %w（mtlsctl eab create で作成する）", "eab_file: %w (create it with mtlsctl eab create)"), err)
	}
	var fed *federation.Builder
	if cfg.Federation.File != "" {
		if fed, err = newFederation(cfg, iss, log); err != nil {
			return err
		}
	}
	srv, err := acmeserver.New(acmeserver.Options{Config: cfg, Issuer: iss, DB: db, EAB: eabStore, Logger: log, Federation: fed})
	if err != nil {
		return err
	}
	defer srv.Close()
	self, err := acmeserver.NewSelfCert(iss, cfg.Hostnames, 7*24*time.Hour)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.RunCleanup(ctx, time.Hour)
	go watchIntermediate(ctx, log, iss, cfg.Cert.Validity.D())

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: self.GetCertificate},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	errc := make(chan error, 2)
	go func() { errc <- hs.ListenAndServeTLS("", "") }()
	servers := []*http.Server{hs}

	if cfg.Admin.Listen != "" {
		adm, err := admin.New(admin.Options{Config: cfg, Issuer: iss, DB: db, EAB: eabStore, Logs: logs, Logger: log, Started: started, Revoke: srv.RevokeByAdmin, Federation: fed})
		if err != nil {
			return err
		}
		as := &http.Server{
			Addr:              cfg.Admin.Listen,
			Handler:           adm.Handler(),
			TLSConfig:         adm.TLSConfig(self.GetCertificate),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    16 << 10,
			// 証明書による拒否（許可されていない名前・別の CA・証明書なし）は TLS の段階で起き、
			// http.Server のエラーログに送信元と理由が出る。監査のため警告として残す。
			ErrorLog: slog.NewLogLogger(log.With("category", "audit", "component", "admin").Handler(), slog.LevelWarn),
		}
		go func() { errc <- as.ListenAndServeTLS("", "") }()
		servers = append(servers, as)
		log.Info(i18n.T("管理画面を起動した", "admin UI started"), "listen", cfg.Admin.Listen, "allowed_clients", cfg.Admin.AllowedClients)
		if len(cfg.Admin.AllowedCIDRs) == 0 && !isLoopback(cfg.Admin.Listen) {
			log.Warn(i18n.T("admin.allowed_cidrs が空で、管理画面が localhost 以外で待ち受けている。管理用のサブネットに限ることを推奨する", "admin.allowed_cidrs is empty and the admin UI listens on a non-localhost address; restricting it to the admin subnet is recommended"))
		}
	}
	log.Info(i18n.T("mtls-ca を起動した", "mtls-ca started"), "version", version.Version, "listen", cfg.Listen, "directory", cfg.ExternalURL+"/acme/directory",
		"allowed_domains", cfg.Policy.AllowedDomains, "cert_validity", cfg.Cert.Validity.D())

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info(i18n.T("停止する", "stopping"))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, s := range servers {
			_ = s.Shutdown(shutdownCtx)
		}
	}
	return nil
}

// watchIntermediate は中間 CA の残りの有効期間を起動時と 1 日ごとに確かめ、近ければ警告する。
// 残りが証明書の有効期間の半分を切ると発行を拒否するので、その前に気づけるようにする。
func watchIntermediate(ctx context.Context, log *slog.Logger, iss *pki.Issuer, validity time.Duration) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		switch remaining := time.Until(iss.Cert.NotAfter); {
		case remaining < validity/2:
			log.Error(i18n.T("中間 CA の有効期限が近いため、証明書を発行できない。中間 CA を更新すること", "the intermediate CA expires soon, so certificates cannot be issued; rotate the intermediate CA"), "not_after", iss.Cert.NotAfter)
		case remaining < 30*24*time.Hour:
			log.Warn(i18n.T("中間 CA の有効期限が近い。中間 CA を更新すること", "the intermediate CA expires soon; rotate the intermediate CA"), "not_after", iss.Cert.NotAfter, "remaining", remaining.Round(time.Hour))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// isLoopback は待ち受けアドレスが localhost（ループバック）かを返す。
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// newFederation は連携版のトラストバンドルを作る準備をする。自分の範囲は中間 CA の名前制約から得るので、
// 名前制約の無い中間 CA では起動しない（設計 6-4）。起動時に一度バンドルを作り、重なりなどの警告を出す。
func newFederation(cfg *config.CA, iss *pki.Issuer, log *slog.Logger) (*federation.Builder, error) {
	roots, err := pki.LoadCerts(cfg.RootCert)
	if err != nil {
		return nil, fmt.Errorf("root_cert: %w", err)
	}
	st, err := federation.NewStore(cfg.Federation.File)
	if err != nil {
		return nil, fmt.Errorf("federation.file: %w", err)
	}
	b, err := federation.NewBuilder(st, iss.Cert, iss.Key, roots, cfg.Federation.BundleValidity.D(), log)
	if err != nil {
		return nil, fmt.Errorf(i18n.T("連携版を使えない: %w", "cannot enable federation: %w"), err)
	}
	if _, _, err := b.Current(time.Now()); err != nil {
		return nil, err
	}
	log.Info(i18n.T("連携版を有効にした", "federation enabled"), "federation_file", cfg.Federation.File, "own_scope", b.OwnScope(), "bundle_validity", cfg.Federation.BundleValidity.D())
	return b, nil
}
