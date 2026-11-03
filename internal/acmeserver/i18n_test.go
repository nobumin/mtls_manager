package acmeserver_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/nobumin/mtls_manager/internal/i18n"
	"github.com/nobumin/mtls_manager/internal/testca"
)

// MTLS_LANG=en のとき、ACME のエラーの説明（detail）は英語になる。
func TestProblemDetailInEnglish(t *testing.T) {
	t.Cleanup(i18n.Set(i18n.English))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	c := newClient(t, ca)
	_, err := c.Register(ctx, &acme.Account{}, acme.AcceptTOS)
	var ae *acme.Error
	if !errors.As(err, &ae) || ae.Detail != "this CA requires External Account Binding" {
		t.Fatalf("detail が英語でない: %v", err)
	}
}
