package nanoca

// Device Attestation support for ACME Device Attestation Extension
// Implements WebAuthn attestation object parsing with proper CBOR decoding.
// Currently supports the "none" attestation format with extensible architecture
// for additional attestation format verifiers (android-key, tpm, etc.).

// AttestationObject represents an ACME Device Attestation object
// Based on WebAuthn attestation object but simplified for ACME use case
// Uses CBOR encoding as per WebAuthn specification
type AttestationObject struct {
	Format  string         `json:"fmt" cbor:"fmt"`
	AttStmt map[string]any `json:"attStmt" cbor:"attStmt"`
}
