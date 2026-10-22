// Package null implements an attestation format that accepts any statement.
// It is for tests and local development only. The client chooses the
// attestation format, so a CA that registers this verifier next to a real
// one lets any client skip attestation.
package null

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/brandonweeks/nanoca"
)

// AttestationVerifier implements the "null" attestation format
// This format is always valid but provides no cryptographic proof. The
// "serial" field carries the claimed permanent identifier and the "pub"
// field carries the key to certify as a DER SubjectPublicKeyInfo.
type AttestationVerifier struct{}

// New creates a new null attestation verifier
func New() *AttestationVerifier {
	return &AttestationVerifier{}
}

// Format returns the attestation format identifier.
func (n *AttestationVerifier) Format() string { return "null" }

// Verify validates a null attestation statement
func (n *AttestationVerifier) Verify(_ context.Context, stmt nanoca.AttestationStatement, _ nanoca.ChallengeBinding) (*nanoca.DeviceInfo, error) {
	if stmt.Format != "null" {
		return nil, fmt.Errorf("format mismatch: expected null, got %s", stmt.Format)
	}

	serial, ok := stmt.AttStmt["serial"].(string)
	if !ok || serial == "" {
		return nil, errors.New("null attestation statement missing serial field")
	}
	pubDER, ok := stmt.AttStmt["pub"].([]byte)
	if !ok {
		return nil, errors.New("null attestation statement missing pub field")
	}
	publicKey, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pub field: %w", err)
	}

	return &nanoca.DeviceInfo{
		PermanentIdentifier: &nanoca.PermanentIdentifier{
			Identifier: serial,
		},
		PublicKey: publicKey,
	}, nil
}

// CreateNullDeviceAttestation creates a null attestation object that names serial and publicKey.
// It is for testing and development, where no real device attestation is available.
func CreateNullDeviceAttestation(serial string, publicKey crypto.PublicKey) (map[string]any, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return map[string]any{
		"fmt":     "null",
		"attStmt": map[string]any{"serial": serial, "pub": pubDER},
	}, nil
}
