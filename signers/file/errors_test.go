package file

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSignerRejectsUncleanPath(t *testing.T) {
	t.Parallel()

	// filepath.Clean("./key.pem") != "./key.pem", so the traversal guard fires.
	if _, err := LoadSigner("./key.pem"); err == nil {
		t.Error("LoadSigner(unclean path) error = nil, want error")
	}
}

func TestLoadSignerRejectsUnsupportedKeyType(t *testing.T) {
	t.Parallel()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ed25519.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	if _, err := LoadSigner(path); err == nil {
		t.Error("LoadSigner(ed25519) error = nil, want unsupported key type error")
	}
}
