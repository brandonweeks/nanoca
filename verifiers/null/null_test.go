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

	tests := []struct {
		name    string
		stmt    nanoca.AttestationStatement
		wantErr bool
	}{
		{
			name:    "valid null attestation",
			stmt:    nanoca.AttestationStatement{Format: "null", AttStmt: map[string]any{}},
			wantErr: false,
		},
		{
			name:    "format mismatch",
			stmt:    nanoca.AttestationStatement{Format: "android-key", AttStmt: map[string]any{}},
			wantErr: true,
		},
		{
			// attStmt content is ignored for the null format
			name:    "non-empty attStmt",
			stmt:    nanoca.AttestationStatement{Format: "null", AttStmt: map[string]any{"key": "value"}},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deviceInfo, err := verifier.Verify(t.Context(), tc.stmt, []byte("challenge"))
			if tc.wantErr {
				if err == nil {
					t.Fatal("Verify() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify() failed: %v", err)
			}
			if deviceInfo.PermanentIdentifier.Identifier != "null-attestation-device" {
				t.Errorf("PermanentIdentifier.Identifier = %s, want null-attestation-device",
					deviceInfo.PermanentIdentifier.Identifier)
			}
		})
	}
}
