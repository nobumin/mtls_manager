package agent

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/nobumin/mtls_manager/internal/pki"
)

// state はエージェントの内部状態。account_key と同じディレクトリの state.json に保存する。
// 出力の設定（chain / fullchain を出すかどうか）に関係なく、更新の判断に必要な情報を持つ。
type state struct {
	// Serial は最後に取得した証明書のシリアル（16 進）。
	Serial string `json:"serial"`
	// ObtainedAt は取得した時刻。CA は NotBefore を時計のずれの分だけ過去にずらすので、
	// 更新時期はこの時刻から数える。
	ObtainedAt time.Time `json:"obtained_at"`
	// IntermediatesPEM は発行時に受け取った中間 CA。チェーンの検証に使う。
	IntermediatesPEM string `json:"intermediates_pem"`
}

func (a *Agent) statePath() string {
	return filepath.Join(filepath.Dir(a.cfg.AccountKey), "state.json")
}

// loadState は内部状態を読む。無い・読めない場合は nil（出力済みのファイルだけで判断する）。
func (a *Agent) loadState() *state {
	data, err := os.ReadFile(a.statePath())
	if err != nil {
		return nil
	}
	st := &state{}
	if json.Unmarshal(data, st) != nil {
		return nil
	}
	return st
}

func (a *Agent) saveState(leaf *x509.Certificate, inters []*x509.Certificate, obtainedAt time.Time) error {
	data, err := json.MarshalIndent(state{
		Serial: serialHex(leaf), ObtainedAt: obtainedAt.UTC(), IntermediatesPEM: string(pki.EncodeCertsPEM(inters...)),
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.statePath()), 0o700); err != nil {
		return err
	}
	return pki.WriteFileAtomic(a.statePath(), append(data, '\n'), 0o600)
}
