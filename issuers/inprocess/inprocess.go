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
	chain  []*x509.Certificate
}

// New creates a new in-process certificate issuer.
//
// The optional chain parameter specifies additional certificates to include
// in the ACME certificate response after the leaf, per RFC 8555 Section 7.4.2.
// Certificates must be ordered issuer-first: the CA that signed the leaf,
// then its issuer, and so on up to (but not necessarily including) the root.
func New(caCert *x509.Certificate, signer crypto.Signer, chain ...*x509.Certificate) *Issuer {
	return &Issuer{
		caCert: caCert,
		signer: signer,
		chain:  chain,
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

	chainRaw := make([][]byte, len(di.chain))
	for i, c := range di.chain {
		chainRaw[i] = c.Raw
	}

	return &nanoca.Certificate{
		Certificate:  x509Cert,
		Raw:          certDER,
		SerialNumber: x509Cert.SerialNumber.String(),
		Chain:        di.chain,
		ChainRaw:     chainRaw,
	}, nil
}
