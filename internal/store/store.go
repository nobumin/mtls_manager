// Package store は CA のアカウント・注文・認可・発行履歴を bbolt（組み込みのキーバリューストア）に保存する。
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ErrNotFound はレコードが無いことを表す。
var ErrNotFound = errors.New("not found")

var (
	bucketAccounts = []byte("accounts")
	bucketThumbs   = []byte("account_by_thumbprint")
	bucketOrders   = []byte("orders")
	bucketAuthzs   = []byte("authzs")
	bucketCerts    = []byte("certs")
)

// 状態（RFC 8555 §7.1.6）。
const (
	StatusPending     = "pending"
	StatusProcessing  = "processing"
	StatusValid       = "valid"
	StatusInvalid     = "invalid"
	StatusDeactivated = "deactivated"
	StatusReady       = "ready"
)

// Problem は保存用のエラー情報。
type Problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

// Account は ACME アカウント。
type Account struct {
	ID         string          `json:"id"`
	Status     string          `json:"status"`
	JWK        json.RawMessage `json:"jwk"`
	Thumbprint string          `json:"thumbprint"`
	Contact    []string        `json:"contact,omitempty"`
	EABKeyID   string          `json:"eab_kid"`
	CreatedAt  time.Time       `json:"created_at"`
}

// Order は注文。状態のうち ready は認可の状態から導くので保存しない。
type Order struct {
	ID         string    `json:"id"`
	AccountID  string    `json:"account_id"`
	Status     string    `json:"status"`
	Expires    time.Time `json:"expires"`
	Names      []string  `json:"names"`
	AuthzIDs   []string  `json:"authz_ids"`
	CertSerial string    `json:"cert_serial,omitempty"`
	Error      *Problem  `json:"error,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Challenge はチャレンジ。
type Challenge struct {
	Type      string     `json:"type"`
	Token     string     `json:"token"`
	Status    string     `json:"status"`
	Validated *time.Time `json:"validated,omitempty"`
	Error     *Problem   `json:"error,omitempty"`
}

// Authz は名前 1 つ分の認可。
type Authz struct {
	ID         string      `json:"id"`
	AccountID  string      `json:"account_id"`
	OrderID    string      `json:"order_id"`
	Name       string      `json:"name"`
	Status     string      `json:"status"`
	Expires    time.Time   `json:"expires"`
	Challenges []Challenge `json:"challenges"`
}

// Cert は発行履歴。
type Cert struct {
	Serial    string    `json:"serial"` // 16 進
	AccountID string    `json:"account_id"`
	OrderID   string    `json:"order_id"`
	Names     []string  `json:"names"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// IssuedAt は発行した時刻（NotBefore は時計のずれに備えて過去にずらしてあるので、表示にはこちらを使う）。
	IssuedAt time.Time `json:"issued_at,omitzero"`
	ChainPEM []byte    `json:"chain_pem"` // 末端 + 中間 CA
	// Pending は署名の前に記録しただけで、まだ発行を完了していないことを表す（ReserveCert）。
	// 署名後にプロセスが落ちても、このシリアルは一覧・失効・CRL の対象になる。
	Pending   bool      `json:"pending,omitempty"`
	Revoked   bool      `json:"revoked,omitempty"`
	RevokedAt time.Time `json:"revoked_at,omitzero"`
	Reason    int       `json:"reason,omitempty"`
}

// DB は保存先。
type DB struct {
	bolt *bolt.DB
}

// Open はデータディレクトリにデータベースを開く。ディレクトリは 0700 で作る。
func Open(dir string) (*DB, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	b, err := bolt.Open(filepath.Join(dir, "mtls-ca.db"), 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("データベースを開けない（別の mtls-ca が動いていないか確認する）: %w", err)
	}
	err = b.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketAccounts, bucketThumbs, bucketOrders, bucketAuthzs, bucketCerts} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		b.Close()
		return nil, err
	}
	return &DB{bolt: b}, nil
}

// Close は閉じる。
func (d *DB) Close() error { return d.bolt.Close() }

func get[T any](tx *bolt.Tx, bucket []byte, key string) (*T, error) {
	v := tx.Bucket(bucket).Get([]byte(key))
	if v == nil {
		return nil, ErrNotFound
	}
	var out T
	if err := json.Unmarshal(v, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func put(tx *bolt.Tx, bucket []byte, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return tx.Bucket(bucket).Put([]byte(key), data)
}

func view[T any](d *DB, bucket []byte, key string) (*T, error) {
	var out *T
	err := d.bolt.View(func(tx *bolt.Tx) error {
		var err error
		out, err = get[T](tx, bucket, key)
		return err
	})
	return out, err
}

func update[T any](d *DB, bucket []byte, key string, fn func(*T) error) (*T, error) {
	var out *T
	err := d.bolt.Update(func(tx *bolt.Tx) error {
		v, err := get[T](tx, bucket, key)
		if err != nil {
			return err
		}
		if err := fn(v); err != nil {
			return err
		}
		out = v
		return put(tx, bucket, key, v)
	})
	return out, err
}

// CreateAccount はアカウントを作る。同じ鍵のアカウントがあれば既存のものを返し、created=false。
func (d *DB) CreateAccount(a *Account) (acct *Account, created bool, err error) {
	err = d.bolt.Update(func(tx *bolt.Tx) error {
		if id := tx.Bucket(bucketThumbs).Get([]byte(a.Thumbprint)); id != nil {
			acct, err = get[Account](tx, bucketAccounts, string(id))
			return err
		}
		if err := put(tx, bucketAccounts, a.ID, a); err != nil {
			return err
		}
		acct, created = a, true
		return tx.Bucket(bucketThumbs).Put([]byte(a.Thumbprint), []byte(a.ID))
	})
	return acct, created, err
}

// Account は ID でアカウントを引く。
func (d *DB) Account(id string) (*Account, error) { return view[Account](d, bucketAccounts, id) }

// AccountByThumbprint は鍵の thumbprint でアカウントを引く。
func (d *DB) AccountByThumbprint(tp string) (*Account, error) {
	var out *Account
	err := d.bolt.View(func(tx *bolt.Tx) error {
		id := tx.Bucket(bucketThumbs).Get([]byte(tp))
		if id == nil {
			return ErrNotFound
		}
		var err error
		out, err = get[Account](tx, bucketAccounts, string(id))
		return err
	})
	return out, err
}

// UpdateAccount はアカウントを更新する。
func (d *DB) UpdateAccount(id string, fn func(*Account) error) (*Account, error) {
	return update(d, bucketAccounts, id, fn)
}

// CreateOrder は注文と認可をまとめて保存する。
func (d *DB) CreateOrder(o *Order, authzs []*Authz) error {
	return d.bolt.Update(func(tx *bolt.Tx) error {
		for _, a := range authzs {
			if err := put(tx, bucketAuthzs, a.ID, a); err != nil {
				return err
			}
		}
		return put(tx, bucketOrders, o.ID, o)
	})
}

// Order は注文を引く。
func (d *DB) Order(id string) (*Order, error) { return view[Order](d, bucketOrders, id) }

// UpdateOrder は注文を更新する。
func (d *DB) UpdateOrder(id string, fn func(*Order) error) (*Order, error) {
	return update(d, bucketOrders, id, fn)
}

// OrdersByAccount はアカウントの注文 ID を返す。
func (d *DB) OrdersByAccount(accountID string) ([]string, error) {
	var ids []string
	err := d.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOrders).ForEach(func(k, v []byte) error {
			var o Order
			if err := json.Unmarshal(v, &o); err != nil {
				return err
			}
			if o.AccountID == accountID {
				ids = append(ids, o.ID)
			}
			return nil
		})
	})
	return ids, err
}

// Authz は認可を引く。
func (d *DB) Authz(id string) (*Authz, error) { return view[Authz](d, bucketAuthzs, id) }

// UpdateAuthz は認可を更新する。
func (d *DB) UpdateAuthz(id string, fn func(*Authz) error) (*Authz, error) {
	return update(d, bucketAuthzs, id, fn)
}

// ReserveCert は署名の前に、これから発行する証明書のシリアルを記録する。
// 署名した後で FinalizeOrder が失敗しても（プロセスが落ちても）、発行したものを必ず失効できるようにする。
func (d *DB) ReserveCert(c *Cert) error {
	c.Pending = true
	return d.bolt.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketCerts).Get([]byte(c.Serial)) != nil {
			return fmt.Errorf("シリアル %s はすでに使われている", c.Serial)
		}
		return put(tx, bucketCerts, c.Serial, c)
	})
}

// DeleteReservedCert は署名に失敗した予約を消す（完了したものは消さない）。
func (d *DB) DeleteReservedCert(serial string) error {
	return d.bolt.Update(func(tx *bolt.Tx) error {
		c, err := get[Cert](tx, bucketCerts, serial)
		if err != nil || !c.Pending {
			return err
		}
		return tx.Bucket(bucketCerts).Delete([]byte(serial))
	})
}

// FinalizeOrder は発行した証明書を保存し、注文を valid にする（1 トランザクション）。
func (d *DB) FinalizeOrder(orderID string, c *Cert) error {
	c.Pending = false
	return d.bolt.Update(func(tx *bolt.Tx) error {
		o, err := get[Order](tx, bucketOrders, orderID)
		if err != nil {
			return err
		}
		if err := put(tx, bucketCerts, c.Serial, c); err != nil {
			return err
		}
		o.Status, o.CertSerial = StatusValid, c.Serial
		return put(tx, bucketOrders, o.ID, o)
	})
}

// Cert は発行履歴を引く。
func (d *DB) Cert(serial string) (*Cert, error) { return view[Cert](d, bucketCerts, serial) }

// UpdateCert は発行履歴を更新する。
func (d *DB) UpdateCert(serial string, fn func(*Cert) error) (*Cert, error) {
	return update(d, bucketCerts, serial, fn)
}

// Certs は保存されているすべての発行履歴を返す。
func (d *DB) Certs() ([]Cert, error) {
	var out []Cert
	err := d.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCerts).ForEach(func(k, v []byte) error {
			var c Cert
			if err := json.Unmarshal(v, &c); err != nil {
				return err
			}
			out = append(out, c)
			return nil
		})
	})
	return out, err
}

// RevokedCerts は失効済みで、まだ有効期限が切れていない証明書を返す（CRL 用）。
func (d *DB) RevokedCerts(now time.Time) ([]Cert, error) {
	var out []Cert
	err := d.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCerts).ForEach(func(k, v []byte) error {
			var c Cert
			if err := json.Unmarshal(v, &c); err != nil {
				return err
			}
			if c.Revoked && c.NotAfter.After(now) {
				out = append(out, c)
			}
			return nil
		})
	})
	return out, err
}

// Cleanup は期限切れから retention を過ぎた注文・認可・発行履歴を消す。
func (d *DB) Cleanup(now time.Time, retention time.Duration) (removed int, err error) {
	limit := now.Add(-retention)
	err = d.bolt.Update(func(tx *bolt.Tx) error {
		sweep := func(bucket []byte, expired func(v []byte) (bool, error)) error {
			// 走査中の削除はカーソルが要素を飛ばし得るので、キーを集めてから消す。
			b := tx.Bucket(bucket)
			var keys [][]byte
			if err := b.ForEach(func(k, v []byte) error {
				ok, err := expired(v)
				if ok {
					keys = append(keys, append([]byte(nil), k...))
				}
				return err
			}); err != nil {
				return err
			}
			for _, k := range keys {
				if err := b.Delete(k); err != nil {
					return err
				}
			}
			removed += len(keys)
			return nil
		}
		if err := sweep(bucketOrders, func(v []byte) (bool, error) {
			var o Order
			err := json.Unmarshal(v, &o)
			return err == nil && o.Expires.Before(limit), err
		}); err != nil {
			return err
		}
		if err := sweep(bucketAuthzs, func(v []byte) (bool, error) {
			var a Authz
			err := json.Unmarshal(v, &a)
			return err == nil && a.Expires.Before(limit), err
		}); err != nil {
			return err
		}
		return sweep(bucketCerts, func(v []byte) (bool, error) {
			var c Cert
			err := json.Unmarshal(v, &c)
			return err == nil && c.NotAfter.Before(limit), err
		})
	})
	return removed, err
}

// ErrAlreadyRevoked はすでに失効していることを表す。
var ErrAlreadyRevoked = errors.New("すでに失効している")

// RevocationReasons は受け付ける失効理由（RFC 5280 §5.3.1）。
// 0: 指定なし, 1: 鍵の漏えい, 3: 所属の変更, 4: 置き換え, 5: 運用停止。
var RevocationReasons = []int{0, 1, 3, 4, 5}

// ValidRevocationReason は受け付ける失効理由かを返す。
func ValidRevocationReason(reason int) bool { return slices.Contains(RevocationReasons, reason) }

// RevokeCert は証明書を失効させる。check が nil でなければ、更新の前に呼ぶ（所有者の確認など）。
// 失効の記録は ACME の revokeCert と mtls-ca revoke の両方がこれを通る。
func (d *DB) RevokeCert(serial string, reason int, check func(*Cert) error) error {
	if !ValidRevocationReason(reason) {
		return fmt.Errorf("失効理由 %d は受け付けない（%v）", reason, RevocationReasons)
	}
	_, err := d.UpdateCert(serial, func(c *Cert) error {
		if check != nil {
			if err := check(c); err != nil {
				return err
			}
		}
		if c.Revoked {
			return ErrAlreadyRevoked
		}
		c.Revoked, c.RevokedAt, c.Reason = true, time.Now().UTC(), reason
		return nil
	})
	return err
}

// ResetProcessingChallenges は確認中（processing）のまま残ったチャレンジを pending に戻す。
// CA が確認の途中で止まった場合に、再起動後にクライアントがやり直せるようにする。起動時に呼ぶ。
func (d *DB) ResetProcessingChallenges() (reset int, err error) {
	err = d.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAuthzs)
		var changed []*Authz
		if err := b.ForEach(func(k, v []byte) error {
			var a Authz
			if err := json.Unmarshal(v, &a); err != nil {
				return err
			}
			hit := false
			for i := range a.Challenges {
				if a.Challenges[i].Status == StatusProcessing {
					a.Challenges[i].Status = StatusPending
					hit = true
				}
			}
			if hit {
				changed = append(changed, &a)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, a := range changed {
			if err := put(tx, bucketAuthzs, a.ID, a); err != nil {
				return err
			}
		}
		reset = len(changed)
		return nil
	})
	return reset, err
}

// Accounts はすべてのアカウントを返す（管理画面用）。
func (d *DB) Accounts() ([]Account, error) {
	var out []Account
	err := d.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAccounts).ForEach(func(k, v []byte) error {
			var a Account
			if err := json.Unmarshal(v, &a); err != nil {
				return err
			}
			out = append(out, a)
			return nil
		})
	})
	return out, err
}

// Issued は発行した時刻を返す（古い記録で IssuedAt が無ければ NotBefore）。
func (c Cert) Issued() time.Time {
	if c.IssuedAt.IsZero() {
		return c.NotBefore
	}
	return c.IssuedAt
}
