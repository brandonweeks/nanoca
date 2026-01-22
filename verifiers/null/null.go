package null

import (
	"context"
	"fmt"

	"github.com/brandonweeks/nanoca"
)

// AttestationVerifier implements the "null" attestation format
// This format is always valid but provides no cryptographic proof
type AttestationVerifier struct{}

// New creates a new null attestation verifier
func New() *AttestationVerifier {
	return &AttestationVerifier{}
}

// Format returns the attestation format identifier.
func (n *AttestationVerifier) Format() string { return "null" }

// Verify validates a null attestation statement
func (n *AttestationVerifier) Verify(_ context.Context, stmt nanoca.AttestationStatement, _ []byte) (*nanoca.DeviceInfo, error) {
	if stmt.Format != "null" {
		return nil, fmt.Errorf("format mismatch: expected null, got %s", stmt.Format)
	}

	// For null attestation, the attStmt should be empty or only contain empty fields
	// We allow an empty map as per the CreateNullDeviceAttestation format

	// For null attestation, create basic device info without any specific device identifiers.
	// RFC 4043: when Assigner is absent, the certificate issuer is the assigner.
	return &nanoca.DeviceInfo{
		PermanentIdentifier: &nanoca.PermanentIdentifier{
			Identifier: "null-attestation-device",
		},
	}, nil
}

// CreateNullDeviceAttestation creates a null ACME Device Attestation object
// for testing and development scenarios where no actual device attestation is available
func CreateNullDeviceAttestation() map[string]any {
	return map[string]any{
		"fmt":     "null",
		"attStmt": map[string]any{},
	}
}
