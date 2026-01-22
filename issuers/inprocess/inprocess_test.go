package inprocess

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/certutil"
)

func createTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	return cert, key
}

func TestIssuer_IssueCertificate(t *testing.T) {
	t.Parallel()

	caCert, signer := createTestCA(t)

	issuer := New(caCert, signer)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CSR key: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Test Device",
			Organization: []string{"Test Org"},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, csrKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	hwTypeOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 2}
	deviceInfos := []*nanoca.DeviceInfo{
		{
			PermanentIdentifier: &nanoca.PermanentIdentifier{
				Identifier: "device-123",
				Assigner:   asn1.ObjectIdentifier{1, 2, 3, 4},
			},
			HardwareModule: &nanoca.HardwareModule{
				Type:  hwTypeOID,
				Value: []byte("UDID-ABC-123"),
			},
		},
	}

	cert, err := issuer.IssueCertificate(csr, deviceInfos)
	if err != nil {
		t.Fatalf("IssueCertificate() error = %v", err)
	}
	if cert == nil {
		t.Fatal("IssueCertificate() returned nil certificate")
	}

	if cert.Certificate == nil {
		t.Error("Certificate.Certificate is nil")
	}
	if len(cert.Raw) == 0 {
		t.Error("Certificate.Raw is empty")
	}
	if cert.SerialNumber == "" {
		t.Error("Certificate.SerialNumber is empty")
	}

	x509Cert := cert.Certificate
	if x509Cert.Subject.CommonName != "Test Device" {
		t.Errorf("Certificate CommonName = %v, want Test Device", x509Cert.Subject.CommonName)
	}
	if x509Cert.Issuer.CommonName != caCert.Subject.CommonName {
		t.Errorf("Certificate Issuer CN = %v, want %v", x509Cert.Issuer.CommonName, caCert.Subject.CommonName)
	}
	if x509Cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Certificate should have DigitalSignature key usage")
	}
	if x509Cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("Certificate should have KeyEncipherment key usage")
	}
	if len(x509Cert.ExtKeyUsage) == 0 || x509Cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Error("Certificate should have ClientAuth extended key usage")
	}

	sanExt := certutil.FindExtension(x509Cert, certutil.OIDSubjectAltName)
	if sanExt == nil {
		t.Fatal("Certificate should have a SubjectAltName extension")
	}

	otherNames, err := certutil.ParseOtherNames(sanExt.Value)
	if err != nil {
		t.Fatalf("ParseOtherNames() error = %v", err)
	}
	foundPI, foundHM := false, false
	for _, on := range otherNames {
		if on.TypeID.Equal(certutil.OIDPermanentIdentifier) {
			foundPI = true
			pi, err := certutil.ParsePermanentIdentifier(on.Value)
			if err != nil {
				t.Fatalf("ParsePermanentIdentifier() error = %v", err)
			}
			if pi.Identifier != "device-123" {
				t.Errorf("PermanentIdentifier.Identifier = %q, want %q", pi.Identifier, "device-123")
			}
			if !pi.Assigner.Equal(asn1.ObjectIdentifier{1, 2, 3, 4}) {
				t.Errorf("PermanentIdentifier.Assigner = %v, want %v", pi.Assigner, asn1.ObjectIdentifier{1, 2, 3, 4})
			}
		}
		if on.TypeID.Equal(certutil.OIDHardwareModuleName) {
			foundHM = true
			hm, err := certutil.ParseHardwareModule(on.Value)
			if err != nil {
				t.Fatalf("ParseHardwareModule() error = %v", err)
			}
			if !hm.Type.Equal(hwTypeOID) {
				t.Errorf("HardwareModule.Type = %v, want %v", hm.Type, hwTypeOID)
			}
			if string(hm.Value) != "UDID-ABC-123" {
				t.Errorf("HardwareModule.Value = %q, want %q", hm.Value, "UDID-ABC-123")
			}
		}
	}
	if !foundPI {
		t.Error("SAN extension should contain a PermanentIdentifier otherName")
	}
	if !foundHM {
		t.Error("SAN extension should contain a HardwareModuleName otherName")
	}
}
