//go:build linux

package application

import (
	"bytes"
	"errors"
	"testing"
)

func TestFinalizeManagedBasicUsesCloseResultBeforeSecretCleanup(t *testing.T) {
	t.Run("close_failure_clears_password", func(t *testing.T) {
		password := []byte("delivered-only-on-success")
		closeFailure := errors.New("deterministic close failure")
		var resultErr error
		finalizeManagedBasic(&resultErr, password, func() error { return closeFailure })
		if !errors.Is(resultErr, closeFailure) {
			t.Fatalf("final error=%v", resultErr)
		}
		if !bytes.Equal(password, make([]byte, len(password))) {
			t.Fatalf("password retained after Close failure: %q", password)
		}
	})

	t.Run("success_preserves_password", func(t *testing.T) {
		password := []byte("deliver-this-password")
		expected := append([]byte(nil), password...)
		var resultErr error
		finalizeManagedBasic(&resultErr, password, func() error { return nil })
		if resultErr != nil {
			t.Fatal(resultErr)
		}
		if !bytes.Equal(password, expected) {
			t.Fatal("successful finalization cleared the delivered password")
		}
	})

	t.Run("existing_failure_clears_password_after_close", func(t *testing.T) {
		password := []byte("must-not-survive")
		resultErr := errors.New("operation failed")
		closed := false
		finalizeManagedBasic(&resultErr, password, func() error {
			closed = true
			return nil
		})
		if !closed || !bytes.Equal(password, make([]byte, len(password))) {
			t.Fatal("final cleanup did not close first and clear the failed result secret")
		}
	})
}
