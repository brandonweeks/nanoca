package file

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadSigner loads a crypto.Signer from a PEM-encoded private key file
func LoadSigner(path string) (crypto.Signer, error) {
	// Clean the path to prevent directory traversal attacks
	cleanPath := filepath.Clean(path)
	if cleanPath != path {
		return nil, errors.New("invalid file path")
	}

	keyData, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return parseSigner(keyData)
}

// parseSigner parses a crypto.Signer from PEM-encoded PKCS #8 private key data
func parseSigner(keyData []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unsupported PEM block type: %s, only PKCS #8 format supported", block.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}
}
