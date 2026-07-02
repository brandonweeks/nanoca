package nanoca

// AttestationObject is a WebAuthn-style CBOR attestation object as used by the
// ACME device attestation extension.
type AttestationObject struct {
	Format  string         `json:"fmt" cbor:"fmt"`
	AttStmt map[string]any `json:"attStmt" cbor:"attStmt"`
}
