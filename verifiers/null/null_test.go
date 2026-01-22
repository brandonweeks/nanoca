package null

import (
	"testing"

	"github.com/brandonweeks/nanoca"
)

func TestAttestationVerifier(t *testing.T) {
	t.Parallel()

	verifier := New()

	// Test valid null attestation
	stmt := nanoca.AttestationStatement{
		Format:  "null",
		AttStmt: map[string]any{},
	}

	deviceInfo, err := verifier.Verify(t.Context(), stmt, []byte("challenge"))
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}

	if deviceInfo.PermanentIdentifier.Identifier != "null-attestation-device" {
		t.Errorf("PermanentIdentifier.Identifier = %s, want null-attestation-device",
			deviceInfo.PermanentIdentifier.Identifier)
	}

	// Test format mismatch
	stmt.Format = "android-key"
	_, err = verifier.Verify(t.Context(), stmt, []byte("challenge"))
	if err == nil {
		t.Error("Verify() should fail with format mismatch")
	}

	// Test with non-empty attStmt - this should still succeed for null attestation
	// as per ACME Device Attestation spec which allows empty or minimal content
	stmt.Format = "null"
	stmt.AttStmt = map[string]any{"key": "value"}
	_, err = verifier.Verify(t.Context(), stmt, []byte("challenge"))
	if err != nil {
		t.Errorf("Verify() should succeed with null attestation regardless of attStmt content: %v", err)
	}
}
