package inprocess

import (
	"bytes"
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

func createTestIntermediateCA(t *testing.T, parentCert *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate intermediate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Test CA Org"},
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse intermediate CA certificate: %v", err)
	}

	return cert, key
}

func newTestCSR(t *testing.T, commonName string) *x509.CertificateRequest {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CSR key: %v", err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	return csr
}

func TestIssuer_IssueCertificate(t *testing.T) {
	t.Parallel()

	caCert, signer := createTestCA(t)

	t.Run("self-signed root issuer stores root, serves leaf only", func(t *testing.T) {
		issuer, err := New(signer, caCert)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		cert, err := issuer.IssueCertificate(newTestCSR(t, "Test Device"), nil)
		if err != nil {
			t.Fatalf("IssueCertificate() error = %v", err)
		}

		// The full chain is stored, including the self-signed root.
		if len(cert.ChainRaw) != 1 || !bytes.Equal(cert.ChainRaw[0], caCert.Raw) {
			t.Fatalf("cert.ChainRaw should contain the root, got %d entries", len(cert.ChainRaw))
		}
		// The served chain omits the self-signed root: leaf only.
		served := cert.ServedChain()
		if len(served) != 1 || !bytes.Equal(served[0], cert.Raw) {
			t.Fatalf("ServedChain should be the leaf only, got %d entries", len(served))
		}
	})

	t.Run("intermediate issuer stores full chain, serves leaf + intermediate", func(t *testing.T) {
		intermCert, intermSigner := createTestIntermediateCA(t, caCert, signer)
		issuer, err := New(intermSigner, intermCert, caCert)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		cert, err := issuer.IssueCertificate(newTestCSR(t, "Test Device With Chain"), nil)
		if err != nil {
			t.Fatalf("IssueCertificate() error = %v", err)
		}

		// The full chain is stored: intermediate then root.
		if len(cert.ChainRaw) != 2 || !bytes.Equal(cert.ChainRaw[0], intermCert.Raw) || !bytes.Equal(cert.ChainRaw[1], caCert.Raw) {
			t.Fatalf("cert.ChainRaw should be [intermediate, root], got %d entries", len(cert.ChainRaw))
		}
		// The served chain is leaf + intermediate; the trailing self-signed
		// root is omitted per RFC 8555 §7.4.2.
		served := cert.ServedChain()
		if len(served) != 2 || !bytes.Equal(served[0], cert.Raw) || !bytes.Equal(served[1], intermCert.Raw) {
			t.Fatalf("ServedChain should be [leaf, intermediate], got %d entries", len(served))
		}
		// The leaf must be signed by the intermediate, not the root.
		if cert.Issuer.CommonName != intermCert.Subject.CommonName {
			t.Errorf("leaf issuer CN = %q, want %q", cert.Issuer.CommonName, intermCert.Subject.CommonName)
		}
	})

	t.Run("nil issuer certificate returns a construction error", func(t *testing.T) {
		if _, err := New(signer, nil); err == nil {
			t.Fatal("New() with a nil issuing certificate should error")
		}
	})

	t.Run("nil entry in chain returns a construction error", func(t *testing.T) {
		intermCert, intermSigner := createTestIntermediateCA(t, caCert, signer)

		if _, err := New(intermSigner, intermCert, nil); err == nil {
			t.Fatal("New() with a nil chain entry should error")
		}
	})

	t.Run("non-self-signed trailing cert is kept in served chain", func(t *testing.T) {
		intermCert, intermSigner := createTestIntermediateCA(t, caCert, signer)
		// No root supplied: the trailing cert is the intermediate, which is
		// not self-signed and therefore must be served.
		issuer, err := New(intermSigner, intermCert)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		cert, err := issuer.IssueCertificate(newTestCSR(t, "Test Device No Root"), nil)
		if err != nil {
			t.Fatalf("IssueCertificate() error = %v", err)
		}

		if len(cert.ChainRaw) != 1 || !bytes.Equal(cert.ChainRaw[0], intermCert.Raw) {
			t.Fatalf("cert.ChainRaw should contain exactly the intermediate certificate, got %d entries", len(cert.ChainRaw))
		}
		served := cert.ServedChain()
		if len(served) != 2 || !bytes.Equal(served[0], cert.Raw) || !bytes.Equal(served[1], intermCert.Raw) {
			t.Fatalf("ServedChain should be [leaf, intermediate], got %d entries", len(served))
		}
	})

	t.Run("leaf carries SAN identifiers and client-auth key usage", func(t *testing.T) {
		issuer, err := New(signer, caCert)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		csr := newTestCSR(t, "Test Device")

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
	})
}
