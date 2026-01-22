package apple

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"github.com/brandonweeks/nanoca"
)

//go:embed Apple_Enterprise_Attestation_Root_CA.pem
var appleRootCertPEM []byte

var (
	appleDeviceSerialOID   = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 1}
	appleDeviceUDIDOID     = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 2}
	appleChallengeNonceOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 11, 1}
)

// AttestationVerifier implements the attestation format used by Managed Device Attestation (MDA)
type AttestationVerifier struct {
	logger       *slog.Logger
	trustedRoots *x509.CertPool
}

// New creates a new Apple attestation verifier
func New(logger *slog.Logger) *AttestationVerifier {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(appleRootCertPEM) {
		panic("failed to parse embedded Apple Enterprise Attestation Root CA certificate")
	}

	return &AttestationVerifier{
		logger:       logger,
		trustedRoots: pool,
	}
}

// Format returns the attestation format identifier.
func (a *AttestationVerifier) Format() string { return "apple" }

// Verify validates an Apple MDA attestation statement
func (a *AttestationVerifier) Verify(ctx context.Context, stmt nanoca.AttestationStatement, challenge []byte) (*nanoca.DeviceInfo, error) {
	if stmt.Format != "apple" {
		return nil, fmt.Errorf("format mismatch: expected apple, got %s", stmt.Format)
	}

	x5cRaw, ok := stmt.AttStmt["x5c"]
	if !ok {
		return nil, errors.New("apple attestation statement missing x5c field")
	}

	x5cSlice, ok := x5cRaw.([]any)
	if !ok {
		return nil, errors.New("x5c field must be an array")
	}

	if len(x5cSlice) == 0 {
		return nil, errors.New("x5c array cannot be empty")
	}

	var certChain []*x509.Certificate
	for i, certBytes := range x5cSlice {
		certBytes, ok := certBytes.([]byte)
		if !ok {
			return nil, fmt.Errorf("x5c[%d] must be a byte slice", i)
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %d: %w", i, err)
		}

		certChain = append(certChain, cert)
	}

	credCert := certChain[0]

	a.logger.DebugContext(ctx, "Attestation certificate", "certificate_pem", string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: credCert.Raw,
	})))

	hasher := sha256.New()
	hasher.Write(challenge)
	expectedNonce := hasher.Sum(nil)

	if err := a.verifyNonceExtension(credCert, expectedNonce); err != nil {
		return nil, fmt.Errorf("nonce verification failed: %w", err)
	}

	if err := a.verifyCertificateChain(certChain); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	deviceInfo := a.extractDeviceInfo(credCert)
	return deviceInfo, nil
}

func (a *AttestationVerifier) verifyNonceExtension(cert *x509.Certificate, expectedNonce []byte) error {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(appleChallengeNonceOID) {
			if subtle.ConstantTimeCompare(ext.Value, expectedNonce) == 1 {
				return nil
			}
			return errors.New("nonce value mismatch")
		}
	}

	return errors.New("apple MDA nonce extension not found in certificate")
}

func (a *AttestationVerifier) verifyCertificateChain(certChain []*x509.Certificate) error {
	if len(certChain) == 0 {
		return errors.New("empty certificate chain")
	}
	leafCert := certChain[0]

	intermediates := x509.NewCertPool()
	for _, cert := range certChain[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         a.trustedRoots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := leafCert.Verify(opts)
	return err
}

func (a *AttestationVerifier) extractDeviceInfo(cert *x509.Certificate) *nanoca.DeviceInfo {
	var serialNumber, udid string

	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(appleDeviceSerialOID):
			serialNumber = string(ext.Value)
		case ext.Id.Equal(appleDeviceUDIDOID):
			udid = string(ext.Value)
		}
	}

	deviceInfo := newDeviceInfo(serialNumber, udid)

	return deviceInfo
}

func newDeviceInfo(serialNumber, udid string) *nanoca.DeviceInfo {
	deviceInfo := &nanoca.DeviceInfo{}

	if serialNumber != "" {
		// RFC 4043: when Assigner is absent, the certificate issuer is the assigner.
		deviceInfo.PermanentIdentifier = &nanoca.PermanentIdentifier{
			Identifier: serialNumber,
		}
	}

	if udid != "" {
		deviceInfo.HardwareModule = &nanoca.HardwareModule{
			Type:  appleDeviceUDIDOID,
			Value: []byte(udid),
		}
	}

	return deviceInfo
}
