package mtlspki

import (
	"os"
	"testing"
)

func TestSecurePrivateKeyPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0600, 0400, 0700} {
		if !securePrivateKeyPermissions(mode) {
			t.Errorf("secure mode %04o was rejected", mode)
		}
	}

	for _, mode := range []os.FileMode{0640, 0604, 0644, 0660, 0666} {
		if securePrivateKeyPermissions(mode) {
			t.Errorf("insecure mode %04o was accepted", mode)
		}
	}
}
