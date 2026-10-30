package store

import (
	"errors"
	"testing"
	"time"
)

func openTest(t *testing.T) *DB {
	t.Helper()
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// 署名の前に記録したシリアルは、発行が完了しなくても失効できる。
func TestReservedCertCanBeRevoked(t *testing.T) {
	db := openTest(t)
	if err := db.ReserveCert(&Cert{Serial: "ab", AccountID: "a", NotAfter: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := db.ReserveCert(&Cert{Serial: "ab"}); err == nil {
		t.Fatal("同じシリアルを二重に予約できた")
	}
	if err := db.RevokeCert("ab", 1, nil); err != nil {
		t.Fatalf("予約のみの証明書を失効できない: %v", err)
	}
	if err := db.RevokeCert("ab", 1, nil); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("二重の失効: %v", err)
	}
	revoked, err := db.RevokedCerts(time.Now())
	if err != nil || len(revoked) != 1 {
		t.Fatalf("CRL の対象 = %d 件, %v", len(revoked), err)
	}
}

func TestFinalizeClearsPendingAndDeleteKeepsFinalized(t *testing.T) {
	db := openTest(t)
	o := &Order{ID: "o1", Status: StatusProcessing, Expires: time.Now().Add(time.Hour)}
	if err := db.CreateOrder(o, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.ReserveCert(&Cert{Serial: "cd", OrderID: "o1"}); err != nil {
		t.Fatal(err)
	}
	if err := db.FinalizeOrder("o1", &Cert{Serial: "cd", OrderID: "o1", ChainPEM: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	c, err := db.Cert("cd")
	if err != nil || c.Pending {
		t.Fatalf("完了後も Pending: %+v, %v", c, err)
	}
	// 完了したものは DeleteReservedCert で消えない。
	if err := db.DeleteReservedCert("cd"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Cert("cd"); err != nil {
		t.Fatalf("完了した証明書が消えた: %v", err)
	}
}

func TestRevokeCertRejectsUnknownReason(t *testing.T) {
	db := openTest(t)
	_ = db.ReserveCert(&Cert{Serial: "ef"})
	if err := db.RevokeCert("ef", 7, nil); err == nil {
		t.Fatal("受け付けない失効理由が通った")
	}
}

func TestResetProcessingChallenges(t *testing.T) {
	db := openTest(t)
	a := &Authz{ID: "z1", Status: StatusPending, Expires: time.Now().Add(time.Hour), Challenges: []Challenge{
		{Type: "http-01", Status: StatusProcessing}, {Type: "tls-alpn-01", Status: StatusPending},
	}}
	if err := db.CreateOrder(&Order{ID: "o1"}, []*Authz{a}); err != nil {
		t.Fatal(err)
	}
	n, err := db.ResetProcessingChallenges()
	if err != nil || n != 1 {
		t.Fatalf("戻した件数 = %d, %v", n, err)
	}
	got, _ := db.Authz("z1")
	if got.Challenges[0].Status != StatusPending {
		t.Fatalf("processing のまま: %+v", got.Challenges)
	}
}
