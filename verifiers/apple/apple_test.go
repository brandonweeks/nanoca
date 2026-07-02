package apple

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"testing"

	"github.com/brandonweeks/nanoca"
)

const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIDQzCCAsigAwIBAgIGAZgITH68MAoGCCqGSM49BAMDMFIxLjAsBgNVBAMMJUFw
cGxlIEVudGVycHJpc2UgQXR0ZXN0YXRpb24gU3ViIENBIDExEzARBgNVBAoMCkFw
cGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTI1MDcxMzA5MzgwN1oXDTI1MTAxMjA5
MzgwN1owgZExSTBHBgNVBAMMQGYzOTk5MDk2YmU0ZjhiMDVhMzQ0MTEyOWI0MmFh
MjE5OGJiYTVjMzk4MTE2NTA5MTY2Y2JmMmNhMTViMGIxYWExGjAYBgNVBAsMEUFB
QSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApD
YWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGjFm6/hVBY2eXsnrxY74
r0cjjN7QFPOv8118zXcUNnYzJ8PPcC+058pSZ1Dme8EN7K/XHVHz8zjM8U1qUP3Q
IjsNb7HsIAwQGim0I3Be4KuYjXslNpk26V+ykK8aUamwo4IBKzCCAScwDAYDVR0T
AQH/BAIwADAOBgNVHQ8BAf8EBAMCBPAwEgYKKoZIhvdjZAgKAgQEMTUuNTASBgoq
hkiG92NkCAoDBAQxNS41MBIGCiqGSIb3Y2QICgEEBDE1LjUwFQYKKoZIhvdjZAgJ
BAQHSjUxNHNBUDAbBgoqhkiG92NkCA0CBA1GdWxsIFNlY3VyaXR5MBEGCiqGSIb3
Y2QIDQEEAwIBADARBgoqhkiG92NkCA0DBAMCAQAwGAYKKoZIhvdjZAgJAQQKVE1X
RldXV1A2NzAnBgoqhkiG92NkCAkCBBkwMDAwNjAzMC0wMDA2NTE2OTBBODQwMDFD
MC4GCiqGSIb3Y2QICwEEIJ/yGcKDExPIGQtj6d2PgKoKSpc3pY2qkx2oq94vLV1i
MAoGCCqGSM49BAMDA2kAMGYCMQD8jJh/9FMtM2BOHQHqXlemYnx1Lpi9QdG/UpZx
TxktrRVyJPTnEndc9mEpLLolQXACMQDorSXJBI1S6JAAnqaL04Lv/Qk2UiW1vOI+
rhjjV2pVj/2R6+4X9EPq4U5WU/gIwLw=
-----END CERTIFICATE-----`

func parseCertFromPEM(certPEM string) *x509.Certificate {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		panic("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	return cert
}

func TestNew(t *testing.T) {
	t.Parallel()

	verifier := New(slog.New(slog.DiscardHandler))
	if verifier == nil {
		t.Fatal("expected non-nil verifier")
	}
	if verifier.trustedRoots == nil {
		t.Fatal("expected non-nil trusted roots")
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	cert := parseCertFromPEM(testCertPEM)

	tests := []struct {
		name      string
		stmt      nanoca.AttestationStatement
		challenge []byte
		wantErr   string
	}{
		{
			name:      "FormatMismatch",
			stmt:      nanoca.AttestationStatement{Format: "tpm", AttStmt: map[string]any{}},
			challenge: []byte("challenge"),
			wantErr:   "format mismatch: expected apple, got tpm",
		},
		{
			name:      "MissingX5C",
			stmt:      nanoca.AttestationStatement{Format: "apple", AttStmt: map[string]any{}},
			challenge: []byte("challenge"),
			wantErr:   "apple attestation statement missing x5c field",
		},
		{
			name:      "InvalidX5CType",
			stmt:      nanoca.AttestationStatement{Format: "apple", AttStmt: map[string]any{"x5c": "not an array"}},
			challenge: []byte("challenge"),
			wantErr:   "x5c field must be an array",
		},
		{
			name:      "EmptyX5C",
			stmt:      nanoca.AttestationStatement{Format: "apple", AttStmt: map[string]any{"x5c": []any{}}},
			challenge: []byte("challenge"),
			wantErr:   "x5c array cannot be empty",
		},
		{
			name:      "InvalidCertificateBytes",
			stmt:      nanoca.AttestationStatement{Format: "apple", AttStmt: map[string]any{"x5c": []any{"not bytes"}}},
			challenge: []byte("challenge"),
			wantErr:   "x5c[0] must be a byte slice",
		},
		{
			name:      "NonceValidation",
			stmt:      nanoca.AttestationStatement{Format: "apple", AttStmt: map[string]any{"x5c": []any{cert.Raw}}},
			challenge: []byte("wrong challenge"),
			wantErr:   "nonce verification failed: nonce value mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			verifier := New(slog.New(slog.DiscardHandler))
			_, err := verifier.Verify(t.Context(), tt.stmt, tt.challenge)
			if err == nil {
				t.Fatalf("expected error %q, got nil", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Errorf("unexpected error message: got %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestExtractDeviceInfo(t *testing.T) {
	t.Parallel()

	cert := parseCertFromPEM(testCertPEM)
	verifier := New(slog.New(slog.DiscardHandler))

	deviceInfo := verifier.extractDeviceInfo(cert)

	if deviceInfo.PermanentIdentifier == nil {
		t.Fatal("expected permanent identifier to be set")
	}
	if deviceInfo.PermanentIdentifier.Identifier != "TMWFWWWP67" {
		t.Errorf("expected serial number TMWFWWWP67, got %s", deviceInfo.PermanentIdentifier.Identifier)
	}
	if len(deviceInfo.PermanentIdentifier.Assigner) > 0 {
		t.Errorf("expected nil assigner (RFC 4043: issuer is the assigner), got %v", deviceInfo.PermanentIdentifier.Assigner)
	}

	if deviceInfo.HardwareModule == nil {
		t.Fatal("expected hardware module to be set")
	}
	if !deviceInfo.HardwareModule.Type.Equal(appleDeviceUDIDOID) {
		t.Errorf("expected type %v, got %v", appleDeviceUDIDOID, deviceInfo.HardwareModule.Type)
	}
	expectedUDID := "00006030-000651690A84001C"
	if string(deviceInfo.HardwareModule.Value) != expectedUDID {
		t.Errorf("expected UDID %s, got %s", expectedUDID, string(deviceInfo.HardwareModule.Value))
	}
}

func TestVerifyNonceExtension_NotFound(t *testing.T) {
	t.Parallel()

	verifier := New(slog.New(slog.DiscardHandler))

	cert := &x509.Certificate{
		Extensions: []pkix.Extension{},
	}

	err := verifier.verifyNonceExtension(cert, []byte("test"))
	if err == nil {
		t.Fatal("expected error for missing nonce extension")
	}
	if err.Error() != "apple MDA nonce extension not found in certificate" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestVerifyCertificateChain_EmptyChain(t *testing.T) {
	t.Parallel()

	verifier := New(slog.New(slog.DiscardHandler))

	err := verifier.verifyCertificateChain([]*x509.Certificate{})
	if err == nil {
		t.Fatal("expected error for empty certificate chain")
	}
	if err.Error() != "empty certificate chain" {
		t.Errorf("unexpected error message: %v", err)
	}
}
