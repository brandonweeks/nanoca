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
