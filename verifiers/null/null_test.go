package null

import (
	"testing"

	"github.com/brandonweeks/nanoca"
)

func TestAttestationVerifier(t *testing.T) {
	t.Parallel()

	verifier := New()

	if got := verifier.Format(); got != "null" {
		t.Errorf("Format() = %q, want null", got)
	}
	if got := CreateNullDeviceAttestation(); got["fmt"] != "null" {
		t.Errorf("CreateNullDeviceAttestation() fmt = %v, want null", got["fmt"])
	}

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

	stmt.Format = "android-key"
	_, err = verifier.Verify(t.Context(), stmt, []byte("challenge"))
	if err == nil {
		t.Error("Verify() should fail with format mismatch")
	}

	stmt.Format = "null"
	stmt.AttStmt = map[string]any{"key": "value"}
	_, err = verifier.Verify(t.Context(), stmt, []byte("challenge"))
	if err != nil {
		t.Errorf("Verify() should succeed with null attestation regardless of attStmt content: %v", err)
	}
}
