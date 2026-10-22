package tpm_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/certutil"
	"github.com/brandonweeks/nanoca/verifiers/tpm"
	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidAIKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
	// oidTPMManufacturer stands in for the hwType of a TPM hardware module.
	oidTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
)

//nolint:gosec // a challenge token and key authorization, not credentials
const (
	testToken   = "ZmFrZS10b2tlbg"
	testKeyAuth = testToken + ".WlhoaGJYQnNaUQ"
)

// algSpec is a COSE algorithm the verifier accepts, with what an AK signing
// under it uses.
type algSpec struct {
	cose    int64
	rsa     bool
	curve   elliptic.Curve
	hash    crypto.Hash
	tpmHash tpm2.TPMIAlgHash
	scheme  tpm2.TPMAlgID
}

var algSpecs = map[string]algSpec{
	"": {
		cose:    -7, // ES256
		curve:   elliptic.P256(),
		hash:    crypto.SHA256,
		tpmHash: tpm2.TPMAlgSHA256,
		scheme:  tpm2.TPMAlgECDSA,
	},
	"es384": {
		cose:    -35,
		curve:   elliptic.P384(),
		hash:    crypto.SHA384,
		tpmHash: tpm2.TPMAlgSHA384,
		scheme:  tpm2.TPMAlgECDSA,
	},
	"rs256": {
		cose:    -257,
		rsa:     true,
		hash:    crypto.SHA256,
		tpmHash: tpm2.TPMAlgSHA256,
		scheme:  tpm2.TPMAlgRSASSA,
	},
}

// binding is what the CA hands a verifier for the challenge the test
// attestations were built against.
func binding(keyAuth string) nanoca.ChallengeBinding {
	return nanoca.ChallengeBinding{Token: testToken, KeyAuthorization: keyAuth}
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// attestation is a TPM key certification assembled in software: the AK signs
// with an ordinary crypto.Signer rather than a TPM, so the structures a TPM
// would emit are built by hand.
type attestation struct {
	root        *x509.Certificate
	rootKey     *ecdsa.PrivateKey
	akCert      *x509.Certificate
	akKey       crypto.Signer
	attestedKey crypto.PublicKey
	// intermediates are the CA certificates between the AK certificate and
	// the root, as x5c carries them.
	intermediates []*x509.Certificate

	alg      int64
	pubArea  []byte
	certInfo []byte
	sig      []byte
}

type attestationOpts struct {
	// alg names the algorithm the AK signs the certification with, a key
	// of algSpecs. The empty value is ES256.
	alg string
	// nameAlg overrides the attested key's name algorithm.
	nameAlg tpm2.TPMIAlgHash
	// permanentIdentifier and hardwareSerial go in the AK certificate's
	// subjectAltName. An empty value omits the entry.
	permanentIdentifier string
	hardwareSerial      string
	// subject, when set, gives the AK certificate a non-empty subject.
	subject string
	// omitAIKEKU drops the tcg-kp-AIKCertificate extended key usage.
	omitAIKEKU bool
	// omitSAN drops the subjectAltName extension.
	omitSAN bool
	// isCA marks the AK certificate as a CA certificate.
	isCA bool
	// expired issues an AK certificate whose validity has ended.
	expired bool
	// intermediate issues the AK certificate from an intermediate CA under
	// the root instead of from the root itself.
	intermediate bool
	// qualifyingData overrides the digest the AK signs over.
	qualifyingData []byte
	// mutatePublic edits the attested key's public area after the
	// certification was signed over the unedited one.
	mutatePublic func(*tpm2.TPMTPublic)
	// attributes overrides the attested key's object attributes.
	attributes *tpm2.TPMAObject
}

func newAttestation(t *testing.T, opts attestationOpts) *attestation {
	t.Helper()

	if opts.permanentIdentifier == "" && opts.hardwareSerial == "" && !opts.omitSAN {
		opts.permanentIdentifier = "0123456789"
	}

	spec, ok := algSpecs[opts.alg]
	if !ok {
		t.Fatalf("unknown alg %q", opts.alg)
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test AK Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("creating root certificate: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parsing root certificate: %v", err)
	}

	var akKey crypto.Signer
	if spec.rsa {
		if akKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			t.Fatalf("generating AK key: %v", err)
		}
	} else if akKey, err = ecdsa.GenerateKey(spec.curve, rand.Reader); err != nil {
		t.Fatalf("generating AK key: %v", err)
	}

	issuer, issuerKey := root, rootKey
	var intermediates []*x509.Certificate
	if opts.intermediate {
		intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating intermediate key: %v", err)
		}
		intermediateTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(3),
			Subject:               pkix.Name{CommonName: "Test AK Intermediate CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, intermediateKey.Public(), rootKey)
		if err != nil {
			t.Fatalf("creating intermediate certificate: %v", err)
		}
		intermediate, err := x509.ParseCertificate(intermediateDER)
		if err != nil {
			t.Fatalf("parsing intermediate certificate: %v", err)
		}
		issuer, issuerKey = intermediate, intermediateKey
		intermediates = []*x509.Certificate{intermediate}
	}

	akTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  opts.isCA,
	}
	if opts.expired {
		akTemplate.NotBefore = time.Now().Add(-2 * time.Hour)
		akTemplate.NotAfter = time.Now().Add(-time.Hour)
	}
	if opts.subject != "" {
		akTemplate.Subject = pkix.Name{CommonName: opts.subject}
	}
	if !opts.omitAIKEKU {
		akTemplate.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidAIKCertificate}
	}
	if !opts.omitSAN {
		akTemplate.ExtraExtensions = []pkix.Extension{
			sanExtension(t, opts.permanentIdentifier, opts.hardwareSerial),
		}
	}
	akDER, err := x509.CreateCertificate(rand.Reader, akTemplate, issuer, akKey.Public(), issuerKey)
	if err != nil {
		t.Fatalf("creating AK certificate: %v", err)
	}
	akCert, err := x509.ParseCertificate(akDER)
	if err != nil {
		t.Fatalf("parsing AK certificate: %v", err)
	}

	attestedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating attested key: %v", err)
	}
	public := eccPublicArea(attestedKey, opts.attributes, opts.nameAlg)

	name, err := tpm2.ObjectName(public)
	if err != nil {
		t.Fatalf("computing object name: %v", err)
	}

	// WebAuthn Level 3 Section 8.3: the qualifying data is the key
	// authorization hashed with the digest the statement's alg names.
	qualifyingData := opts.qualifyingData
	if qualifyingData == nil {
		digest := spec.hash.New()
		digest.Write([]byte(testKeyAuth))
		qualifyingData = digest.Sum(nil)
	}

	certInfo := tpm2.Marshal(tpm2.TPMSAttest{
		Magic: tpm2.TPMGeneratedValue,
		Type:  tpm2.TPMSTAttestCertify,
		ExtraData: tpm2.TPM2BData{
			Buffer: qualifyingData,
		},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify, &tpm2.TPMSCertifyInfo{
			Name:          *name,
			QualifiedName: *name,
		}),
	})

	if opts.mutatePublic != nil {
		opts.mutatePublic(public)
	}

	return &attestation{
		root:          root,
		rootKey:       rootKey,
		akCert:        akCert,
		akKey:         akKey,
		attestedKey:   attestedKey.Public(),
		intermediates: intermediates,
		alg:           spec.cose,
		pubArea:       tpm2.Marshal(public),
		certInfo:      certInfo,
		sig:           signCertInfo(t, akKey, certInfo, spec),
	}
}

// tokenDigest is the SHA-256 of the token alone, which a client that binds
// the token instead of the key authorization would sign over.
func tokenDigest() []byte {
	digest := sha256.Sum256([]byte(testToken))
	return digest[:]
}

// eccPublicArea builds the TPMT_PUBLIC a TPM would hold for an ECDSA P-256
// signing key.
func eccPublicArea(key *ecdsa.PrivateKey, attributes *tpm2.TPMAObject, nameAlg tpm2.TPMIAlgHash) *tpm2.TPMTPublic {
	attrs := tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		SignEncrypt:         true,
	}
	if attributes != nil {
		attrs = *attributes
	}
	if nameAlg == 0 {
		nameAlg = tpm2.TPMAlgSHA256
	}
	return &tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          nameAlg,
		ObjectAttributes: attrs,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: key.X.FillBytes(make([]byte, 32))},
			Y: tpm2.TPM2BECCParameter{Buffer: key.Y.FillBytes(make([]byte, 32))},
		}),
	}
}

func signCertInfo(t *testing.T, akKey crypto.Signer, certInfo []byte, spec algSpec) []byte {
	t.Helper()

	digest := spec.hash.New()
	digest.Write(certInfo)
	hashed := digest.Sum(nil)

	switch key := akKey.(type) {
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, hashed)
		if err != nil {
			t.Fatalf("signing certInfo: %v", err)
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		return tpm2.Marshal(tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
				Hash:       spec.tpmHash,
				SignatureR: tpm2.TPM2BECCParameter{Buffer: r.FillBytes(make([]byte, size))},
				SignatureS: tpm2.TPM2BECCParameter{Buffer: s.FillBytes(make([]byte, size))},
			}),
		})
	case *rsa.PrivateKey:
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, spec.hash, hashed)
		if err != nil {
			t.Fatalf("signing certInfo: %v", err)
		}
		return tpm2.Marshal(tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSASSA, &tpm2.TPMSSignatureRSA{
				Hash: spec.tpmHash,
				Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: signature},
			}),
		})
	default:
		t.Fatalf("unsupported AK key type %T", akKey)
		return nil
	}
}

// sanExtension builds a critical subjectAltName holding the otherName entries
// a TCG AK certificate names the device with.
func sanExtension(t *testing.T, permanentIdentifier, hardwareSerial string) pkix.Extension {
	t.Helper()

	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		if permanentIdentifier != "" {
			certutil.AddPermanentIdentifierOtherName(b, &nanoca.PermanentIdentifier{
				Identifier: permanentIdentifier,
			})
		}
		if hardwareSerial != "" {
			certutil.AddHardwareModuleOtherName(b, &nanoca.HardwareModule{
				Type:  oidTPMManufacturer,
				Value: []byte(hardwareSerial),
			})
		}
	})
	value, err := b.Bytes()
	if err != nil {
		t.Fatalf("encoding subjectAltName: %v", err)
	}
	return pkix.Extension{Id: certutil.OIDSubjectAltName, Critical: true, Value: value}
}

func (a *attestation) statement() nanoca.AttestationStatement {
	x5c := []any{a.akCert.Raw}
	for _, intermediate := range a.intermediates {
		x5c = append(x5c, intermediate.Raw)
	}
	return nanoca.AttestationStatement{
		Format: "tpm",
		AttStmt: map[string]any{
			"ver":      "2.0",
			"alg":      a.alg,
			"x5c":      x5c,
			"sig":      a.sig,
			"certInfo": a.certInfo,
			"pubArea":  a.pubArea,
		},
	}
}

func (a *attestation) roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.root)
	return pool
}

func (a *attestation) verifier(t *testing.T) *tpm.AttestationVerifier {
	t.Helper()

	verifier, err := tpm.New(discardLogger(), a.roots())
	if err != nil {
		t.Fatalf("tpm.New() error = %v", err)
	}
	return verifier
}

func TestFormat(t *testing.T) {
	t.Parallel()

	att := newAttestation(t, attestationOpts{})
	if got := att.verifier(t).Format(); got != "tpm" {
		t.Errorf("Format() = %q, want tpm", got)
	}
}

func TestNewRequiresRoots(t *testing.T) {
	t.Parallel()

	if _, err := tpm.New(discardLogger(), nil); err == nil {
		t.Error("New(nil roots) error = nil, want error")
	}
	if _, err := tpm.New(discardLogger(), x509.NewCertPool()); err == nil {
		t.Error("New(empty roots) error = nil, want error")
	}
	if _, err := tpm.New(nil, x509.NewCertPool()); err == nil {
		t.Error("New(nil logger) error = nil, want error")
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	att := newAttestation(t, attestationOpts{
		permanentIdentifier: "C02XY1234567",
		hardwareSerial:      "ek-digest",
	})

	deviceInfo, err := att.verifier(t).Verify(t.Context(), att.statement(), binding(testKeyAuth))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if deviceInfo.PermanentIdentifier == nil {
		t.Fatal("Verify() returned no permanent identifier")
	}
	if got := deviceInfo.PermanentIdentifier.Identifier; got != "C02XY1234567" {
		t.Errorf("PermanentIdentifier.Identifier = %q, want C02XY1234567", got)
	}
	if len(deviceInfo.PermanentIdentifier.Assigner) > 0 {
		t.Errorf("PermanentIdentifier.Assigner = %v, want empty", deviceInfo.PermanentIdentifier.Assigner)
	}

	if deviceInfo.HardwareModule == nil {
		t.Fatal("Verify() returned no hardware module")
	}
	if !deviceInfo.HardwareModule.Type.Equal(oidTPMManufacturer) {
		t.Errorf("HardwareModule.Type = %v, want %v", deviceInfo.HardwareModule.Type, oidTPMManufacturer)
	}
	if got := string(deviceInfo.HardwareModule.Value); got != "ek-digest" {
		t.Errorf("HardwareModule.Value = %q, want ek-digest", got)
	}

	// The CA certifies the attested key from pubArea, not the AK.
	attested, ok := deviceInfo.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey is %T, want *ecdsa.PublicKey", deviceInfo.PublicKey)
	}
	if !attested.Equal(att.attestedKey) {
		t.Error("PublicKey is not the key from pubArea")
	}
}

// The AK may sign with any algorithm the verifier accepts, and the
// qualifying data follows that algorithm's digest.
func TestVerifyAlgorithms(t *testing.T) {
	t.Parallel()

	for _, alg := range []string{"es384", "rs256"} {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()

			att := newAttestation(t, attestationOpts{alg: alg})
			if _, err := att.verifier(t).Verify(t.Context(), att.statement(), binding(testKeyAuth)); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

// A statement whose qualifying data is hashed with SHA-256 while alg names
// SHA-384 does not bind the key authorization under WebAuthn Section 8.3.
func TestVerifyRejectsMismatchedQualifyingDigest(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte(testKeyAuth))
	att := newAttestation(t, attestationOpts{alg: "es384", qualifyingData: digest[:]})

	_, err := att.verifier(t).Verify(t.Context(), att.statement(), binding(testKeyAuth))
	if err == nil {
		t.Fatal("Verify() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "qualifying data =") {
		t.Errorf("Verify() error = %q, want a qualifying data failure", err)
	}
}

func TestVerifyHardwareModuleOnly(t *testing.T) {
	t.Parallel()

	att := newAttestation(t, attestationOpts{hardwareSerial: "ek-digest"})

	deviceInfo, err := att.verifier(t).Verify(t.Context(), att.statement(), binding(testKeyAuth))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if deviceInfo.PermanentIdentifier != nil {
		t.Error("Verify() returned a permanent identifier the certificate does not name")
	}
	if deviceInfo.HardwareModule == nil {
		t.Fatal("Verify() returned no hardware module")
	}
}

// x5c may carry the intermediates between the AK certificate and the root,
// and the chain fails without them.
func TestVerifyIntermediate(t *testing.T) {
	t.Parallel()

	att := newAttestation(t, attestationOpts{intermediate: true})

	if _, err := att.verifier(t).Verify(t.Context(), att.statement(), binding(testKeyAuth)); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	stmt := att.statement()
	stmt.AttStmt["x5c"] = []any{att.akCert.Raw}
	_, err := att.verifier(t).Verify(t.Context(), stmt, binding(testKeyAuth))
	if err == nil {
		t.Fatal("Verify() without the intermediate error = nil, want error")
	}
	if !strings.Contains(err.Error(), "certificate chain verification failed") {
		t.Errorf("Verify() without the intermediate error = %q, want a chain failure", err)
	}
}

func TestVerifyRejectsBadStatements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// format overrides the statement's attestation format.
		format string
		// opts build an attestation whose statement is rejected as-is.
		opts attestationOpts
		// mutate edits an otherwise valid statement.
		mutate  func(*attestation, map[string]any)
		keyAuth string
		wantErr string
	}{
		{
			name:    "FormatMismatch",
			format:  "apple",
			wantErr: "format mismatch: expected tpm, got apple",
		},
		{
			name:    "MissingVer",
			mutate:  func(_ *attestation, stmt map[string]any) { delete(stmt, "ver") },
			wantErr: "tpm attestation statement missing ver field",
		},
		{
			name:    "UnsupportedVer",
			mutate:  func(_ *attestation, stmt map[string]any) { stmt["ver"] = "1.2" },
			wantErr: `unsupported TPM version "1.2"`,
		},
		{
			name:    "MissingAlg",
			mutate:  func(_ *attestation, stmt map[string]any) { delete(stmt, "alg") },
			wantErr: "tpm attestation statement missing alg field",
		},
		{
			name:    "UnsupportedAlg",
			mutate:  func(_ *attestation, stmt map[string]any) { stmt["alg"] = int64(-8) },
			wantErr: "unsupported COSE algorithm -8",
		},
		{
			name:    "AlgMismatch",
			mutate:  func(_ *attestation, stmt map[string]any) { stmt["alg"] = int64(-257) },
			wantErr: "key certification rejected: AK certificate holds an ECDSA key, but alg names an RSA algorithm",
		},
		{
			name:    "MissingPubArea",
			mutate:  func(_ *attestation, stmt map[string]any) { delete(stmt, "pubArea") },
			wantErr: "tpm attestation statement missing pubArea field",
		},
		{
			name:    "EmptyCertInfo",
			mutate:  func(_ *attestation, stmt map[string]any) { stmt["certInfo"] = []byte{} },
			wantErr: "tpm attestation statement has an empty certInfo field",
		},
		{
			name:    "MissingSig",
			mutate:  func(_ *attestation, stmt map[string]any) { delete(stmt, "sig") },
			wantErr: "tpm attestation statement missing sig field",
		},
		{
			name:    "MissingX5C",
			mutate:  func(_ *attestation, stmt map[string]any) { delete(stmt, "x5c") },
			wantErr: "tpm attestation statement missing x5c field",
		},
		{
			name:    "X5CNotArray",
			mutate:  func(_ *attestation, stmt map[string]any) { stmt["x5c"] = "nope" },
			wantErr: "x5c field must be an array",
		},
		{
			name:    "X5CEmpty",
			mutate:  func(_ *attestation, stmt map[string]any) { stmt["x5c"] = []any{} },
			wantErr: "x5c array cannot be empty",
		},
		{
			name:    "X5CEntryNotBytes",
			mutate:  func(_ *attestation, stmt map[string]any) { stmt["x5c"] = []any{"nope"} },
			wantErr: "x5c[0] must be a byte slice",
		},
		{
			name:    "X5CEntryNotCertificate",
			mutate:  func(_ *attestation, stmt map[string]any) { stmt["x5c"] = []any{[]byte("garbage")} },
			wantErr: "failed to parse certificate 0",
		},
		{
			name:    "MalformedPubArea",
			mutate:  func(_ *attestation, stmt map[string]any) { stmt["pubArea"] = []byte("garbage") },
			wantErr: "failed to parse pubArea",
		},
		{
			name:    "MalformedCertInfo",
			mutate:  func(_ *attestation, stmt map[string]any) { stmt["certInfo"] = []byte("garbage") },
			wantErr: "key certification rejected: DecodeAttestationData() failed",
		},
		{
			name:    "KeyAuthorizationMismatch",
			keyAuth: testToken + ".c29tZS1vdGhlci1hY2NvdW50",
			wantErr: "key certification rejected: qualifying data =",
		},
		{
			name:    "QualifyingDataIsTheToken",
			opts:    attestationOpts{qualifyingData: tokenDigest()},
			wantErr: "key certification rejected: qualifying data =",
		},
		{
			name:    "QualifyingDataIsNotHashed",
			opts:    attestationOpts{qualifyingData: []byte(testKeyAuth)},
			wantErr: "key certification rejected: qualifying data =",
		},
		{
			name: "CertifiesAnotherKey",
			opts: attestationOpts{mutatePublic: func(public *tpm2.TPMTPublic) {
				unique, err := public.Unique.ECC()
				if err != nil {
					panic(err)
				}
				unique.X.Buffer[0] ^= 0xff
			}},
			wantErr: "key certification rejected: certification refers to a different key",
		},
		{
			name: "ExportableKey",
			opts: attestationOpts{attributes: &tpm2.TPMAObject{
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			}},
			wantErr: "key certification rejected: provided key is exportable",
		},
		{
			name: "DuplicableKey",
			opts: attestationOpts{attributes: &tpm2.TPMAObject{
				FixedTPM:            true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			}},
			wantErr: "key certification rejected: provided key can be duplicated to a different parent",
		},
		{
			name: "ImportedKey",
			opts: attestationOpts{attributes: &tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				SignEncrypt:  true,
			}},
			wantErr: "key certification rejected: provided key is not created by TPM",
		},
		{
			name: "RestrictedKey",
			opts: attestationOpts{attributes: &tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				Restricted:          true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			}},
			wantErr: "key certification rejected: provided key is restricted",
		},
		{
			name: "DecryptOnlyKey",
			opts: attestationOpts{attributes: &tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Decrypt:             true,
			}},
			wantErr: "attested key rejected: key cannot sign",
		},
		{
			name:    "NonEmptyAKSubject",
			opts:    attestationOpts{subject: "AK"},
			wantErr: "AK certificate rejected: certificate subject is not empty",
		},
		{
			name:    "MissingAIKExtendedKeyUsage",
			opts:    attestationOpts{omitAIKEKU: true},
			wantErr: "AK certificate rejected: certificate is missing the tcg-kp-AIKCertificate extended key usage",
		},
		{
			name:    "AKIsCACertificate",
			opts:    attestationOpts{isCA: true},
			wantErr: "AK certificate rejected: certificate is a CA certificate",
		},
		{
			name:    "ExpiredAKCertificate",
			opts:    attestationOpts{expired: true},
			wantErr: "certificate chain verification failed",
		},
		{
			name:    "MissingSubjectAltName",
			opts:    attestationOpts{omitSAN: true},
			wantErr: "AK certificate has no subjectAltName",
		},
		{
			// The name is the only binding between pubArea and the
			// signed certification, so a collision-prone name
			// algorithm weakens it.
			name:    "WeakNameAlgorithm",
			opts:    attestationOpts{nameAlg: tpm2.TPMAlgSHA1},
			wantErr: "attested key rejected: unsupported name algorithm 0x4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			att := newAttestation(t, tt.opts)
			stmt := att.statement()
			if tt.mutate != nil {
				tt.mutate(att, stmt.AttStmt)
			}
			if tt.format != "" {
				stmt.Format = tt.format
			}
			keyAuth := tt.keyAuth
			if keyAuth == "" {
				keyAuth = testKeyAuth
			}

			_, err := att.verifier(t).Verify(t.Context(), stmt, binding(keyAuth))
			if err == nil {
				t.Fatalf("Verify() error = nil, want %q", tt.wantErr)
			}
			if !strings.HasPrefix(err.Error(), tt.wantErr) {
				t.Errorf("Verify() error = %q, want prefix %q", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyRejectsForgedSignature(t *testing.T) {
	t.Parallel()

	att := newAttestation(t, attestationOpts{})
	stmt := att.statement()
	sig := append([]byte(nil), att.sig...)
	sig[len(sig)-1] ^= 0xff
	stmt.AttStmt["sig"] = sig

	_, err := att.verifier(t).Verify(t.Context(), stmt, binding(testKeyAuth))
	if err == nil {
		t.Fatal("Verify() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "key certification rejected") {
		t.Errorf("Verify() error = %q, want a certification failure", err)
	}
}

func TestVerifyRejectsUntrustedAKCertificate(t *testing.T) {
	t.Parallel()

	att := newAttestation(t, attestationOpts{})
	other := newAttestation(t, attestationOpts{})

	verifier, err := tpm.New(discardLogger(), other.roots())
	if err != nil {
		t.Fatalf("tpm.New() error = %v", err)
	}

	_, err = verifier.Verify(t.Context(), att.statement(), binding(testKeyAuth))
	if err == nil {
		t.Fatal("Verify() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "certificate chain verification failed") {
		t.Errorf("Verify() error = %q, want a chain failure", err)
	}
}
