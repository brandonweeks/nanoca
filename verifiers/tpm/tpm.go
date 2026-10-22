// Package tpm verifies TPM 2.0 attestation for ACME device attestation.
//
// A device proves that the key it asks the CA to certify lives in its TPM
// with a key certification: the attested key in pubArea, the TPMS_ATTEST
// produced by TPM2_Certify in certInfo, and the attestation key's (AK)
// signature over it in sig. The AK is identified by an AK certificate in
// x5c, which the CA chains to a configured root. The AK certificate names
// the device; the attested key in pubArea is the key the CA certifies. The
// fields are carried as the "tpm" statement format of WebAuthn Level 3
// Section 8.3. The certification itself is checked by go-attestation.
package tpm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/certutil"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"
)

// oidAIKCertificate is tcg-kp-AIKCertificate, the extended key usage every AK
// certificate carries (TCG EK Credential Profile, Section 3.2).
var oidAIKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 3}

// coseAlg describes a COSE algorithm identifier from the statement's "alg"
// field: whether the AK signs with RSASSA-PKCS1-v1_5 or ECDSA, and the digest
// the signature and the qualifying data use.
type coseAlg struct {
	rsa  bool
	hash crypto.Hash
}

var coseAlgs = map[int64]coseAlg{
	-7:   {hash: crypto.SHA256},            // ES256
	-35:  {hash: crypto.SHA384},            // ES384
	-36:  {hash: crypto.SHA512},            // ES512
	-257: {rsa: true, hash: crypto.SHA256}, // RS256
	-258: {rsa: true, hash: crypto.SHA384}, // RS384
	-259: {rsa: true, hash: crypto.SHA512}, // RS512
}

// AttestationVerifier implements the TPM 2.0 attestation statement format.
type AttestationVerifier struct {
	logger *slog.Logger
	roots  *x509.CertPool
}

// New creates a TPM attestation verifier that accepts AK certificates
// chaining to roots. There is no industry-wide root for AK certificates: the
// pool holds the roots of the attestation CA that issues AK certificates to
// the operator's devices, after that CA has bound each AK to an endorsement
// key it trusts.
func New(logger *slog.Logger, roots *x509.CertPool) (*AttestationVerifier, error) {
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	if roots == nil || roots.Equal(x509.NewCertPool()) {
		return nil, errors.New("at least one trusted AK certificate root is required")
	}
	return &AttestationVerifier{logger: logger, roots: roots}, nil
}

// Format returns the attestation format identifier.
func (v *AttestationVerifier) Format() string { return "tpm" }

// Verify validates a TPM 2.0 key certification and returns the device
// identity named by the AK certificate along with the attested key.
func (v *AttestationVerifier) Verify(ctx context.Context, stmt nanoca.AttestationStatement, binding nanoca.ChallengeBinding) (*nanoca.DeviceInfo, error) {
	if stmt.Format != "tpm" {
		return nil, fmt.Errorf("format mismatch: expected tpm, got %s", stmt.Format)
	}

	ver, ok := stmt.AttStmt["ver"].(string)
	if !ok {
		return nil, errors.New("tpm attestation statement missing ver field")
	}
	if ver != "2.0" {
		return nil, fmt.Errorf("unsupported TPM version %q", ver)
	}

	rawAlg, ok := cborInt(stmt.AttStmt["alg"])
	if !ok {
		return nil, errors.New("tpm attestation statement missing alg field")
	}
	alg, ok := coseAlgs[rawAlg]
	if !ok {
		return nil, fmt.Errorf("unsupported COSE algorithm %d", rawAlg)
	}

	pubArea, err := byteField(stmt.AttStmt, "pubArea")
	if err != nil {
		return nil, err
	}
	certInfo, err := byteField(stmt.AttStmt, "certInfo")
	if err != nil {
		return nil, err
	}
	sig, err := byteField(stmt.AttStmt, "sig")
	if err != nil {
		return nil, err
	}

	certChain, err := parseX5C(stmt.AttStmt)
	if err != nil {
		return nil, err
	}
	akCert := certChain[0]

	attestedKey, err := tpm2.DecodePublic(pubArea)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pubArea: %w", err)
	}
	publicKey, err := verifyAttestedKey(attestedKey)
	if err != nil {
		return nil, fmt.Errorf("attested key rejected: %w", err)
	}

	// draft-ietf-acme-device-attest-10 Section 5: the key authorization is
	// what attToBeSigned conveys. TPM2_Certify carries it as the
	// qualifying data, which binds the certification to both this
	// challenge and the account key. WebAuthn Level 3 Section 8.3 hashes
	// it with the digest alg names.
	digest := alg.hash.New()
	digest.Write([]byte(binding.KeyAuthorization))
	if err := verifyCertification(akCert.PublicKey, alg, pubArea, certInfo, sig, digest.Sum(nil)); err != nil {
		return nil, fmt.Errorf("key certification rejected: %w", err)
	}

	if err := verifyAKCertificate(akCert); err != nil {
		return nil, fmt.Errorf("AK certificate rejected: %w", err)
	}
	if err := v.verifyCertificateChain(certChain); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	deviceInfo, err := deviceInfoFromAKCertificate(akCert)
	if err != nil {
		return nil, err
	}
	deviceInfo.PublicKey = publicKey

	v.logger.DebugContext(ctx, "Verified TPM key certification",
		"ak_subject", akCert.Subject.String(),
		"ak_issuer", akCert.Issuer.String(),
		"ak_serial", akCert.SerialNumber.String())

	return deviceInfo, nil
}

// verifyAttestedKey applies the checks on the key in pubArea that
// attest.CertificationParameters.Verify leaves out, then returns it as a
// crypto.PublicKey.
func verifyAttestedKey(pub tpm2.Public) (crypto.PublicKey, error) {
	// The name is what binds this public area to the signed certification,
	// so a weak name algorithm would let a collision substitute another
	// key for the one the TPM certified.
	switch pub.NameAlg {
	case tpm2.AlgSHA256, tpm2.AlgSHA384, tpm2.AlgSHA512:
	default:
		return nil, fmt.Errorf("unsupported name algorithm 0x%x", uint16(pub.NameAlg))
	}
	// The CA certifies the key from a CSR it signs.
	if pub.Attributes&tpm2.FlagSign == 0 {
		return nil, errors.New("key cannot sign")
	}

	publicKey, err := pub.Key()
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}
	return publicKey, nil
}

// verifyCertification hands the certification to go-attestation, which
// checks the attested key's attributes, size and curve, that certInfo names
// the key in pubArea and carries the qualifying data, and the AK signature
// over certInfo. go-attestation takes only the digest from the caller, so the
// AK's key type is matched to alg first.
func verifyCertification(akPublicKey crypto.PublicKey, alg coseAlg, pubArea, certInfo, sig, qualifyingData []byte) error {
	switch akPublicKey.(type) {
	case *rsa.PublicKey:
		if !alg.rsa {
			return errors.New("AK certificate holds an RSA key, but alg names an ECDSA algorithm")
		}
	case *ecdsa.PublicKey:
		if alg.rsa {
			return errors.New("AK certificate holds an ECDSA key, but alg names an RSA algorithm")
		}
	default:
		return fmt.Errorf("AK certificate holds a %T key", akPublicKey)
	}

	params := attest.CertificationParameters{
		Public:            pubArea,
		CreateAttestation: certInfo,
		CreateSignature:   sig,
	}
	return params.Verify(attest.VerifyOpts{
		Public:         akPublicKey,
		Hash:           alg.hash,
		QualifyingData: qualifyingData,
	})
}

// verifyAKCertificate applies the AK certificate requirements of WebAuthn
// Level 3 Section 8.3.1, which follow the TCG AK certificate profile: an
// end-entity certificate with an empty subject, the AK extended key usage,
// and the device identity in a SubjectAltName.
func verifyAKCertificate(cert *x509.Certificate) error {
	if cert.Version != 3 {
		return fmt.Errorf("certificate is version %d, want 3", cert.Version)
	}
	// An AK certificate carries the device identity in its SubjectAltName,
	// so the subject is empty: an empty RDNSequence DER-encodes to the
	// two-byte empty SEQUENCE.
	if len(cert.RawSubject) != 2 {
		return errors.New("certificate subject is not empty")
	}
	if cert.BasicConstraintsValid && cert.IsCA {
		return errors.New("certificate is a CA certificate")
	}
	for _, eku := range cert.UnknownExtKeyUsage {
		if eku.Equal(oidAIKCertificate) {
			return nil
		}
	}
	return errors.New("certificate is missing the tcg-kp-AIKCertificate extended key usage")
}

func (v *AttestationVerifier) verifyCertificateChain(certChain []*x509.Certificate) error {
	leaf := certChain[0]

	intermediates := x509.NewCertPool()
	for _, cert := range certChain[1:] {
		intermediates.AddCert(cert)
	}

	// An AK certificate has an empty subject, so its SubjectAltName is
	// critical, and it holds only otherName entries that crypto/x509 does
	// not parse. The parser reports such an extension as unhandled, which
	// would fail verification; the otherNames are read by
	// deviceInfoFromAKCertificate instead.
	leaf = clearUnhandledSAN(leaf)

	opts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	_, err := leaf.Verify(opts)
	return err
}

// clearUnhandledSAN returns a shallow copy of cert with the SubjectAltName
// extension dropped from UnhandledCriticalExtensions.
func clearUnhandledSAN(cert *x509.Certificate) *x509.Certificate {
	var unhandled []asn1.ObjectIdentifier
	for _, oid := range cert.UnhandledCriticalExtensions {
		if !oid.Equal(certutil.OIDSubjectAltName) {
			unhandled = append(unhandled, oid)
		}
	}
	if len(unhandled) == len(cert.UnhandledCriticalExtensions) {
		return cert
	}
	copied := *cert
	copied.UnhandledCriticalExtensions = unhandled
	return &copied
}

// deviceInfoFromAKCertificate reads the device identity from the AK
// certificate's SubjectAltName: a PermanentIdentifier (RFC 4043), a
// HardwareModuleName (RFC 4108), or both.
func deviceInfoFromAKCertificate(cert *x509.Certificate) (*nanoca.DeviceInfo, error) {
	sanExt := certutil.FindExtension(cert, certutil.OIDSubjectAltName)
	if sanExt == nil {
		return nil, errors.New("AK certificate has no subjectAltName")
	}
	otherNames, err := certutil.ParseOtherNames(sanExt.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AK certificate subjectAltName: %w", err)
	}

	deviceInfo := &nanoca.DeviceInfo{}
	for _, otherName := range otherNames {
		switch {
		case otherName.TypeID.Equal(certutil.OIDPermanentIdentifier):
			if deviceInfo.PermanentIdentifier != nil {
				return nil, errors.New("AK certificate has more than one permanentIdentifier")
			}
			permanentIdentifier, err := certutil.ParsePermanentIdentifier(otherName.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to parse permanentIdentifier: %w", err)
			}
			deviceInfo.PermanentIdentifier = permanentIdentifier
		case otherName.TypeID.Equal(certutil.OIDHardwareModuleName):
			if deviceInfo.HardwareModule != nil {
				return nil, errors.New("AK certificate has more than one hardwareModuleName")
			}
			hardwareModule, err := certutil.ParseHardwareModule(otherName.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to parse hardwareModuleName: %w", err)
			}
			deviceInfo.HardwareModule = hardwareModule
		}
	}

	if deviceInfo.PermanentIdentifier == nil && deviceInfo.HardwareModule == nil {
		return nil, errors.New("AK certificate names no permanentIdentifier or hardwareModuleName")
	}
	return deviceInfo, nil
}

func parseX5C(attStmt map[string]any) ([]*x509.Certificate, error) {
	raw, ok := attStmt["x5c"]
	if !ok {
		return nil, errors.New("tpm attestation statement missing x5c field")
	}
	entries, ok := raw.([]any)
	if !ok {
		return nil, errors.New("x5c field must be an array")
	}
	if len(entries) == 0 {
		return nil, errors.New("x5c array cannot be empty")
	}

	var certChain []*x509.Certificate
	for i, entry := range entries {
		der, ok := entry.([]byte)
		if !ok {
			return nil, fmt.Errorf("x5c[%d] must be a byte slice", i)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %d: %w", i, err)
		}
		certChain = append(certChain, cert)
	}
	return certChain, nil
}

func byteField(attStmt map[string]any, name string) ([]byte, error) {
	value, ok := attStmt[name].([]byte)
	if !ok {
		return nil, fmt.Errorf("tpm attestation statement missing %s field", name)
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("tpm attestation statement has an empty %s field", name)
	}
	return value, nil
}

// cborInt reads an integer from a decoded CBOR value, which carries a signed
// COSE algorithm identifier as int64 and an unsigned one as uint64.
func cborInt(value any) (int64, bool) {
	switch v := value.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case uint64:
		if v > 1<<62 {
			return 0, false
		}
		return int64(v), true
	}
	return 0, false
}
