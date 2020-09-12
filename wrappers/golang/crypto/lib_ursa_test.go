package crypto

import (
	"testing"
)

func TestNewNonce(t *testing.T) {
	t.Run("NewNonce", func(t *testing.T) {
		n, err := NewNonce()
		if n == "" {
			t.Errorf("NewNonce() returned blank value")
		}

		if err != nil {
			t.Errorf("NewNonce() returned error")
		}
	})
}
