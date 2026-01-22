package inprocess

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/certutil"
)

// Issuer implements the CertificateIssuer interface with a basic certificate generation approach
type Issuer struct {
	caCert *x509.Certificate
	signer crypto.Signer
}

// New creates a new in-process certificate issuer
func New(caCert *x509.Certificate, signer crypto.Signer) *Issuer {
	return &Issuer{
		caCert: caCert,
		signer: signer,
	}
}

// IssueCertificate creates a certificate from CSR and device information
func (di *Issuer) IssueCertificate(csr *x509.CertificateRequest, deviceInfos []*nanoca.DeviceInfo) (*nanoca.Certificate, error) {
	template := &x509.Certificate{
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	sanExt, err := certutil.BuildSANExtension(deviceInfos, csr)
	if err != nil {
		return nil, fmt.Errorf("failed to build SAN extension: %w", err)
	}
	if sanExt != nil {
		template.ExtraExtensions = append(template.ExtraExtensions, *sanExt)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, di.caCert, csr.PublicKey, di.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	return &nanoca.Certificate{
		Certificate:  x509Cert,
		Raw:          certDER,
		SerialNumber: x509Cert.SerialNumber.String(),
	}, nil
}
