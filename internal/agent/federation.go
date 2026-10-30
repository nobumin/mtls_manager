package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nobumin/mtls_manager/internal/federation"
	"github.com/nobumin/mtls_manager/internal/pki"
)

// 連携版（設計 8.）: CA からトラストバンドルを取得し、検証して書き出す。
//   - バンドルの検証（署名者・自分のルート・範囲の重なりなど）は federation.Verify
//   - 古いバンドルの再送の拒否（エポックと連番）は、ここで内部状態と比べて行う
//   - 停止した・期限切れの連携先のファイルは、消さずに「どこにもつながらない PEM」に置き換える
//   - 更新後のコマンド（hooks.post_bundle）の失敗は、指数バックオフで成功するまで再試行する

// bundleState はトラストバンドルの内部状態（<account_key>.bundle.json）。
type bundleState struct {
	Epoch    string    `json:"epoch"`
	Seq      uint64    `json:"seq"`
	IssuedAt time.Time `json:"issued_at"`
	Expires  time.Time `json:"expires"`
	// Expired は、期限切れで連携先を外したことを表す（同じ処理を繰り返さないため）。
	Expired bool `json:"expired,omitempty"`
	// HookPending は、更新後のコマンドがまだ成功していないことを表す（再起動しても再試行し、check で分かるように）。
	HookPending bool `json:"hook_pending,omitempty"`
	// HookFailed は、更新後のコマンドが失敗したことを表す。
	HookFailed bool `json:"hook_failed,omitempty"`
}

// fedRuntime はプロセスの中だけで持つ状態。
type fedRuntime struct {
	etag        string
	hookNext    time.Time
	hookBackoff backoff
	lastErr     string
	dummy       []byte
}

func (a *Agent) bundleStatePath() string { return a.cfg.AccountKey + ".bundle.json" }

func (a *Agent) loadBundleState() *bundleState {
	data, err := os.ReadFile(a.bundleStatePath())
	if err != nil {
		return nil
	}
	st := &bundleState{}
	if json.Unmarshal(data, st) != nil {
		return nil
	}
	return st
}

func (a *Agent) saveBundleState(st *bundleState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.bundleStatePath()), 0o700); err != nil {
		return err
	}
	return pki.WriteFileAtomic(a.bundleStatePath(), append(data, '\n'), 0o600)
}

// bundleURL は CA の ACME ディレクトリの URL から、トラストバンドルの URL を作る。
func (a *Agent) bundleURL() string {
	u, err := url.Parse(a.cfg.CAURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/federation/bundle"
}

// ownIntermediate は、いまの証明書を発行した中間 CA（自分の中間 CA）を返す。
func (a *Agent) ownIntermediate() (*x509.Certificate, error) {
	certs, err := pki.LoadCerts(a.cfg.Output.Cert)
	if err != nil {
		return nil, errors.New("証明書がまだ無い（取得の後にトラストバンドルを取得する）")
	}
	for _, c := range a.intermediates(a.loadState()) {
		if certs[0].CheckSignatureFrom(c) == nil {
			return c, nil
		}
	}
	return nil, errors.New("証明書を発行した中間 CA が分からない")
}

// verifyOptions はバンドルの検証の条件を、自分のルート（ca_root）と自分の中間 CA の名前制約から作る（CA の応答からは取らない）。
func (a *Agent) verifyOptions(now time.Time) (federation.VerifyOptions, error) {
	inter, err := a.ownIntermediate()
	if err != nil {
		return federation.VerifyOptions{}, err
	}
	scope, err := federation.OwnScope(inter, a.pool, nil)
	if err != nil {
		return federation.VerifyOptions{}, err
	}
	return federation.VerifyOptions{OwnRoots: a.roots, OwnScope: scope, SignerConstraints: inter.PermittedDNSDomains, Now: now}, nil
}

// SyncBundle はトラストバンドルを取得・検証し、変わっていれば書き出す。期限切れなら連携先を外す。
// 更新後のコマンドの再試行もここで行う。連携版を使わない設定では何もしない。
func (a *Agent) SyncBundle(ctx context.Context, now time.Time) error {
	if !a.cfg.FederationEnabled() {
		return nil
	}
	err := a.syncBundle(ctx, now)
	st := a.loadBundleState()
	if st != nil && !st.Expired && !now.Before(st.Expires) {
		a.log.Error("トラストバンドルの有効期限が切れた。連携先をすべて外す（CA との通信を確認する）", "expires", st.Expires)
		if werr := a.writeFederation(nil, ""); werr != nil {
			a.log.Error("連携先のファイルを書けない", "err", werr)
		} else {
			st.Expired, st.HookPending = true, true
			_ = a.saveBundleState(st)
			a.fed.hookNext = time.Time{}
		}
	}
	a.retryBundleHook(ctx, now)
	switch {
	case err != nil && err.Error() != a.fed.lastErr:
		a.log.Warn("トラストバンドルを更新できない（手元のものを有効期限まで使う）", "err", err)
		a.fed.lastErr = err.Error()
	case err == nil && a.fed.lastErr != "":
		a.log.Info("トラストバンドルを取得できるようになった")
		a.fed.lastErr = ""
	}
	return err
}

func (a *Agent) syncBundle(ctx context.Context, now time.Time) error {
	opts, err := a.verifyOptions(now)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.bundleURL(), nil)
	if err != nil {
		return err
	}
	if a.fed.etag != "" {
		req.Header.Set("If-None-Match", a.fed.etag)
	}
	res, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("トラストバンドルを取得できない: %w", err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusNotModified:
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("トラストバンドルを取得できない（HTTP %d。CA の federation.file を確認する）", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	compact := strings.TrimSpace(string(body))
	v, err := federation.Verify(compact, opts)
	if err != nil {
		return fmt.Errorf("トラストバンドルを受け入れない: %w", err)
	}
	b := v.Bundle
	prev := a.loadBundleState()
	if prev != nil {
		switch {
		case b.Epoch == prev.Epoch && b.Seq == prev.Seq:
			a.fed.etag = res.Header.Get("ETag")
			return nil
		case b.Epoch == prev.Epoch && b.Seq < prev.Seq:
			return fmt.Errorf("古いトラストバンドル（連番 %d < %d）を受け入れない", b.Seq, prev.Seq)
		case b.Epoch != prev.Epoch && !b.IssuedAt.After(prev.IssuedAt):
			return fmt.Errorf("エポックが変わったのに、発行時刻（%s）が手元のもの（%s）より新しくない", b.IssuedAt, prev.IssuedAt)
		case b.Epoch != prev.Epoch:
			a.log.Warn("トラストバンドルのエポックが変わった（CA の再起動・復旧）", "epoch", b.Epoch, "previous", prev.Epoch)
		}
	}
	for _, d := range v.Dropped {
		a.log.Error("トラストバンドルの連携先を外した", "reason", d)
	}
	if err := a.writeFederation(v.Partners, compact); err != nil {
		return err
	}
	if err := a.saveBundleState(&bundleState{Epoch: b.Epoch, Seq: b.Seq, IssuedAt: b.IssuedAt, Expires: b.Expires, HookPending: true}); err != nil {
		return err
	}
	a.fed.etag = res.Header.Get("ETag")
	ids := make([]string, 0, len(v.Partners))
	for _, p := range v.Partners {
		ids = append(ids, p.ID)
	}
	a.log.Info("トラストバンドルを更新した", "epoch", b.Epoch, "seq", b.Seq, "partners", ids, "expires", b.Expires)
	a.fed.hookNext = time.Time{}
	a.fed.hookBackoff.reset()
	return nil
}

// writeFederation は出力を書く。partners が nil なら（期限切れ）、連携先をすべて「どこにもつながらない PEM」にする。
func (a *Agent) writeFederation(partners []federation.TrustedPartner, compact string) error {
	if a.cfg.Output.TrustBundle != "" && compact != "" {
		if err := writeFile(a.cfg.Output.TrustBundle, []byte(compact+"\n"), 0o644); err != nil {
			return err
		}
	}
	dir := a.cfg.Output.FederationDir
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, p := range partners {
		if err := writeFile(filepath.Join(dir, p.ID+".pem"), pki.EncodeCertsPEM(p.Roots...), 0o644); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(dir, p.ID+".domains"), []byte(strings.Join(p.Domains, "\n")+"\n"), 0o644); err != nil {
			return err
		}
		keep[p.ID] = true
	}
	// バンドルに無くなった連携先（停止・期限切れ）は、消さずに置き換える（消すと nginx の reload が失敗し、古い信頼が残るため）。
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".pem")
		if !ok || keep[id] || federation.ValidateID(id) != nil {
			continue
		}
		if a.fed.dummy == nil {
			if a.fed.dummy, err = federation.DummyRootPEM(); err != nil {
				return err
			}
		}
		if err := writeFile(filepath.Join(dir, e.Name()), a.fed.dummy, 0o644); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(dir, id+".domains"), nil, 0o644); err != nil {
			return err
		}
		a.log.Warn("連携先を外した（どこにもつながらない PEM に置き換えた）", "partner", id)
	}
	return nil
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	return pki.WriteFileAtomic(path, data, perm)
}

// retryBundleHook は、更新後のコマンドを（必要なら）実行する。失敗したら指数バックオフで再試行する。
func (a *Agent) retryBundleHook(ctx context.Context, now time.Time) {
	st := a.loadBundleState()
	if st == nil || !st.HookPending {
		return
	}
	argv := a.cfg.Hooks.PostBundle
	if len(argv) == 0 {
		st.HookPending, st.HookFailed = false, false
		_ = a.saveBundleState(st)
		return
	}
	if now.Before(a.fed.hookNext) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.cfg.Hooks.Timeout.D())
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "MTLS_AGENT_TRUST_BUNDLE="+a.cfg.Output.TrustBundle, "MTLS_AGENT_FEDERATION_DIR="+a.cfg.Output.FederationDir)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		wait := jitter(a.fed.hookBackoff.next())
		a.fed.hookNext = now.Add(wait)
		st.HookFailed = true
		_ = a.saveBundleState(st)
		a.log.Error("トラストバンドルの更新後のコマンドが失敗した（再試行する。連携先の変更が反映されていない可能性がある）",
			"command", argv, "err", err, "output", truncate(buf.String(), 2000), "retry_in", wait.Round(time.Second))
		return
	}
	st.HookPending, st.HookFailed = false, false
	_ = a.saveBundleState(st)
	a.fed.hookBackoff.reset()
	a.log.Info("トラストバンドルの更新後のコマンドを実行した", "command", argv)
}

// BundleProblem は連携版の状態の問題を返す（mtls-agent check で使う）。問題が無ければ空。
func (a *Agent) BundleProblem(now time.Time) string {
	if !a.cfg.FederationEnabled() {
		return ""
	}
	st := a.loadBundleState()
	switch {
	case st == nil:
		return "トラストバンドルをまだ取得していない"
	case !now.Before(st.Expires):
		return "トラストバンドルの有効期限が切れている（連携先をすべて外している）"
	case st.HookFailed:
		return "トラストバンドルの更新後のコマンドが失敗し続けている"
	case st.Expires.Sub(now) < 24*time.Hour:
		return "トラストバンドルの有効期限が 1 日を切っている（CA から取得できていない）"
	}
	return ""
}

// BundleSummary は連携版の状態の要約を返す（mtls-agent check の表示用）。
func (a *Agent) BundleSummary() string {
	st := a.loadBundleState()
	if st == nil {
		return "未取得"
	}
	var ids []string
	if dir := a.cfg.Output.FederationDir; dir != "" {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if id, ok := strings.CutSuffix(e.Name(), ".domains"); ok {
				if fi, err := e.Info(); err == nil && fi.Size() > 0 {
					ids = append(ids, id)
				}
			}
		}
		slices.Sort(ids)
	}
	return fmt.Sprintf("連番 %d（エポック %.8s）、有効期限 %s、連携先 %v", st.Seq, st.Epoch, st.Expires.Local().Format(time.RFC3339), ids)
}
