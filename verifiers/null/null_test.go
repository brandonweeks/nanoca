package null

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/brandonweeks/nanoca"
)

func TestAttestationVerifier(t *testing.T) {
	t.Parallel()

	verifier := New()

	if got := verifier.Format(); got != "null" {
		t.Errorf("Format() = %q, want null", got)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	att, err := CreateNullDeviceAttestation("SN123", key.Public())
	if err != nil {
		t.Fatalf("CreateNullDeviceAttestation() error = %v", err)
	}
	if att["fmt"] != "null" {
		t.Errorf("CreateNullDeviceAttestation() fmt = %v, want null", att["fmt"])
	}
	attStmt := att["attStmt"].(map[string]any)

	tests := []struct {
		name    string
		stmt    nanoca.AttestationStatement
		wantErr bool
	}{
		{
			name:    "valid null attestation",
			stmt:    nanoca.AttestationStatement{Format: "null", AttStmt: attStmt},
			wantErr: false,
		},
		{
			name:    "format mismatch",
			stmt:    nanoca.AttestationStatement{Format: "android-key", AttStmt: attStmt},
			wantErr: true,
		},
		{
			name:    "missing pub",
			stmt:    nanoca.AttestationStatement{Format: "null", AttStmt: map[string]any{"serial": "SN123"}},
			wantErr: true,
		},
		{
			name:    "missing serial",
			stmt:    nanoca.AttestationStatement{Format: "null", AttStmt: map[string]any{"pub": attStmt["pub"]}},
			wantErr: true,
		},
		{
			name:    "malformed pub",
			stmt:    nanoca.AttestationStatement{Format: "null", AttStmt: map[string]any{"serial": "SN123", "pub": []byte{0x30, 0x00}}},
			wantErr: true,
		},
		{
			name:    "extra attStmt fields",
			stmt:    nanoca.AttestationStatement{Format: "null", AttStmt: map[string]any{"serial": "SN123", "pub": attStmt["pub"], "key": "value"}},
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
			if deviceInfo.PermanentIdentifier.Identifier != "SN123" {
				t.Errorf("PermanentIdentifier.Identifier = %s, want SN123",
					deviceInfo.PermanentIdentifier.Identifier)
			}
			if !key.PublicKey.Equal(deviceInfo.PublicKey) {
				t.Errorf("PublicKey = %v, want the key from pub", deviceInfo.PublicKey)
			}
		})
	}
}
