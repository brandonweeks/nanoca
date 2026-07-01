package inprocess

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/certutil"
)

// Issuer implements the CertificateIssuer interface with a basic certificate generation approach
type Issuer struct {
	caCert   *x509.Certificate
	signer   crypto.Signer
	chainRaw [][]byte
}

// New creates a new in-process certificate issuer.
//
// issuerCert is the certificate whose key (signer) signs issued leaves. rest
// continues the chain toward the root: rest[0] certifies issuerCert, and so on.
// The full chain is stored on each issued certificate; the ACME certificate
// response omits a trailing self-signed root at serve time per RFC 8555
// Section 7.4.2 (see nanoca.Certificate.ServedChain).
//
//	New(signer, root)               // root signs leaves; serves leaf only
//	New(signer, intermediate, root) // intermediate signs leaves; serves leaf + intermediate
func New(signer crypto.Signer, issuerCert *x509.Certificate, rest ...*x509.Certificate) (*Issuer, error) {
	chain := append([]*x509.Certificate{issuerCert}, rest...)
	chainRaw := make([][]byte, len(chain))
	for i, c := range chain {
		if c == nil {
			return nil, errors.New("issuing certificate chain contains a nil certificate")
		}
		chainRaw[i] = c.Raw
	}
	return &Issuer{
		caCert:   issuerCert,
		signer:   signer,
		chainRaw: chainRaw,
	}, nil
}

// IssueCertificate creates a certificate from CSR and device information
func (i *Issuer) IssueCertificate(csr *x509.CertificateRequest, deviceInfos []*nanoca.DeviceInfo) (*nanoca.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		Subject:               csr.Subject,
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
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

	certDER, err := x509.CreateCertificate(rand.Reader, template, i.caCert, csr.PublicKey, i.signer)
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
		ChainRaw:     i.chainRaw,
	}, nil
}
