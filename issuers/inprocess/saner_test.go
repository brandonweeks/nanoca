package inprocess

import (
	"testing"

	"github.com/brandonweeks/nanoca"
)

func TestIssueCertificateSANError(t *testing.T) {
	t.Parallel()

	caCert, caKey := createTestCA(t)
	intermCert, intermKey := createTestIntermediateCA(t, caCert, caKey)

	issuer, err := New(intermKey, intermCert, caCert)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	bad := []*nanoca.DeviceInfo{{HardwareModule: &nanoca.HardwareModule{}}}
	if _, err := issuer.IssueCertificate(t.Context(), newTestCSR(t, "device"), bad); err == nil {
		t.Error("IssueCertificate() error = nil, want SAN build error")
	}
}
