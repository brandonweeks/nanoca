package file

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSigner(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("Failed to marshal test key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	err = os.WriteFile(keyPath, keyPEM, 0o600)
	if err != nil {
		t.Fatalf("Failed to write test key file: %v", err)
	}

	signer, err := LoadSigner(keyPath)
	if err != nil {
		t.Errorf("LoadSigner() error = %v", err)
	}
	if signer == nil {
		t.Error("LoadSigner() returned nil signer")
	}

	if _, ok := signer.(*ecdsa.PrivateKey); !ok {
		t.Errorf("LoadSigner() returned wrong type: %T", signer)
	}

	if _, err = LoadSigner(filepath.Join(tmpDir, "nonexistent.key")); err == nil {
		t.Error("LoadSigner() should fail for nonexistent file")
	}

	if _, err = LoadSigner("../../../etc/passwd"); err == nil {
		t.Error("LoadSigner() should fail for invalid path")
	}
}

func TestParseSigner_PKCS8PrivateKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		keyGen  func() (crypto.PrivateKey, error)
		keyType string
	}{
		{
			name: "RSA PKCS8",
			keyGen: func() (crypto.PrivateKey, error) {
				return rsa.GenerateKey(rand.Reader, 2048)
			},
			keyType: "*rsa.PrivateKey",
		},
		{
			name: "ECDSA PKCS8",
			keyGen: func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			},
			keyType: "*ecdsa.PrivateKey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			privKey, err := tt.keyGen()
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			keyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
			if err != nil {
				t.Fatalf("Failed to marshal PKCS8 key: %v", err)
			}

			keyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyBytes,
			})

			signer, err := parseSigner(keyPEM)
			if err != nil {
				t.Errorf("parseSigner() error = %v", err)
			}
			if signer == nil {
				t.Error("parseSigner() returned nil")
			}

			switch tt.keyType {
			case "*rsa.PrivateKey":
				if _, ok := signer.(*rsa.PrivateKey); !ok {
					t.Errorf("parseSigner() returned wrong type: %T", signer)
				}
			case "*ecdsa.PrivateKey":
				if _, ok := signer.(*ecdsa.PrivateKey); !ok {
					t.Errorf("parseSigner() returned wrong type: %T", signer)
				}
			}
		})
	}
}

func TestParseSigner_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		keyData []byte
		wantErr bool
	}{
		{
			name:    "invalid PEM",
			keyData: []byte("not a pem block"),
			wantErr: true,
		},
		{
			name: "unsupported PEM type",
			keyData: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte("dummy"),
			}),
			wantErr: true,
		},
		{
			name: "invalid PKCS8 key data",
			keyData: pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: []byte("invalid key data"),
			}),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signer, err := parseSigner(tt.keyData)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSigner() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && signer == nil {
				t.Error("parseSigner() returned nil without error")
			}
		})
	}
}
