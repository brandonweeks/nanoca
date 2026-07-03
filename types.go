package nanoca

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type AttestationStatement struct {
	Format   string
	AttStmt  map[string]any
	AuthData []byte // optional, may be omitted per spec
}

// DeviceInfo contains extracted device information from attestation
//
// This structure follows the ACME Device Attestation draft specification.
// PermanentIdentifier contains device serial numbers or similar persistent identifiers.
// HardwareModule contains hardware-specific identifiers like UDIDs or TPM data.
type DeviceInfo struct {
	PermanentIdentifier *PermanentIdentifier
	HardwareModule      *HardwareModule
}

// PermanentIdentifier represents a permanent-identifier as defined in RFC 4043.
//
//	PermanentIdentifier ::= SEQUENCE {
//	    identifierValue  UTF8String        OPTIONAL,
//	    assigner         OBJECT IDENTIFIER OPTIONAL
//	}
type PermanentIdentifier struct {
	Identifier string
	Assigner   asn1.ObjectIdentifier
}

// HardwareModule represents a hardware-module name as defined in RFC 4108.
//
//	HardwareModuleName ::= SEQUENCE {
//	    hwType       OBJECT IDENTIFIER,
//	    hwSerialNum  OCTET STRING
//	}
type HardwareModule struct {
	Type  asn1.ObjectIdentifier
	Value []byte
}

// Certificate holds an issued certificate and its full DER-encoded issuing
// chain. ChainRaw is ordered issuer first and includes a trailing self-signed
// root if one was supplied; it is persisted to storage as-is. The ACME
// certificate response is built by ServedChain, which omits the root.
type Certificate struct {
	*x509.Certificate `json:"-"`
	// ID is the storage and URL identifier; the CA sets it to the order ID.
	ID           string   `json:"id"`
	Raw          []byte   `json:"raw"`
	SerialNumber string   `json:"serialNumber"`
	ChainRaw     [][]byte `json:"chainRaw,omitempty"`
}

// ServedChain returns the DER certificates for the ACME certificate response:
// the leaf (Raw) followed by the issuing chain, with a trailing self-signed
// root omitted per RFC 8555 Section 7.4.2 (clients already hold the root).
func (c *Certificate) ServedChain() [][]byte {
	chain := c.ChainRaw
	if n := len(chain); n > 0 && isSelfSignedDER(chain[n-1]) {
		chain = chain[:n-1]
	}
	return append([][]byte{c.Raw}, chain...)
}

// isSelfSignedDER reports whether a DER certificate is a self-signed root: its
// subject equals its issuer and it is signed by its own key. The signature
// check distinguishes a true root from a merely self-issued certificate (e.g. a
// key-rollover bridge cert, subject==issuer but signed by a different key) that
// must still be served. Unparseable input is treated as not self-signed, so it
// is still served.
func isSelfSignedDER(der []byte) bool {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return false
	}
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert,omitempty"`
	KeyChange  string `json:"keyChange,omitempty"`
	Meta       *Meta  `json:"meta,omitempty"`
}

type Meta struct {
	TermsOfService          string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CAAIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"`
}

type Nonce struct {
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"createdAt"`
}

type Account struct {
	ID                   string           `json:"id"`
	Key                  *jose.JSONWebKey `json:"key,omitempty"`
	KeyThumbprint        string           `json:"keyThumbprint,omitempty"`
	Status               string           `json:"status"`
	Contact              []string         `json:"contact,omitempty"`
	TermsOfServiceAgreed bool             `json:"termsOfServiceAgreed,omitempty"`
	Orders               string           `json:"orders,omitempty"`
	CreatedAt            time.Time        `json:"createdAt"`
}

type AccountRequest struct {
	Contact              []string `json:"contact,omitempty"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed,omitempty"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting,omitempty"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Reservation marks a record as exclusively held by one in-flight operation.
// It is persisted by storage but scrubbed from ACME responses; a reservation
// older than the configured lease was abandoned by a crashed holder and may
// be reclaimed.
type Reservation struct {
	Token      string    `json:"token"`
	ReservedAt time.Time `json:"reservedAt"`
}

// Live reports whether the reservation is still honored under lease. A nil
// reservation on a processing record counts as expired so a malformed
// record can be reclaimed rather than wedged.
func (r *Reservation) Live(lease time.Duration) bool {
	return r != nil && time.Since(r.ReservedAt) <= lease
}

type Order struct {
	ID             string       `json:"id"`
	Status         string       `json:"status"`
	Expires        *time.Time   `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      *time.Time   `json:"notBefore,omitempty"`
	NotAfter       *time.Time   `json:"notAfter,omitempty"`
	Error          *Problem     `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	AccountID      string       `json:"accountId"`
	CreatedAt      time.Time    `json:"createdAt"`
	Reservation    *Reservation `json:"reservation,omitempty"`
}

type OrderRequest struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   *time.Time   `json:"notBefore,omitempty"`
	NotAfter    *time.Time   `json:"notAfter,omitempty"`
}

const (
	OrderStatusPending    = "pending"
	OrderStatusReady      = "ready"
	OrderStatusProcessing = "processing"
	OrderStatusValid      = "valid"
	OrderStatusInvalid    = "invalid"
)

const (
	IdentifierTypePermanentIdentifier = "permanent-identifier"
	IdentifierTypeHardwareModule      = "hardware-module"
)

type Authorization struct {
	ID         string      `json:"id"`
	Status     string      `json:"status"`
	Expires    *time.Time  `json:"expires,omitempty"`
	Identifier Identifier  `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
	Wildcard   bool        `json:"wildcard,omitempty"`
	AccountID  string      `json:"accountId"`
	OrderID    string      `json:"orderId"`
	CreatedAt  time.Time   `json:"createdAt"`
}

type Challenge struct {
	Type      string     `json:"type"`
	URL       string     `json:"url"`
	Status    string     `json:"status"`
	Validated *time.Time `json:"validated,omitempty"`
	Error     *Problem   `json:"error,omitempty"`
	Token     string     `json:"token"`
	KeyAuth   string     `json:"keyAuthorization,omitempty"`
	ID        string     `json:"id"`
	AuthzID   string     `json:"authzId"`
	CreatedAt time.Time  `json:"createdAt"`
	// Attestation holds the raw CBOR attestation object from the validated
	// challenge response, verbatim: finalize re-verifies it, and a decoded
	// copy would not survive storage serialization intact (CBOR byte
	// strings do not round-trip through JSON).
	Attestation []byte       `json:"attestation,omitempty"`
	Reservation *Reservation `json:"reservation,omitempty"`
}

type ChallengeRequest struct {
	// AttObj contains the base64url-encoded WebAuthn attestation object
	// as specified in draft-ietf-acme-device-attest-01
	AttObj string `json:"attObj"`
}

const (
	AuthzStatusPending = "pending"
	AuthzStatusValid   = "valid"
	AuthzStatusInvalid = "invalid"
	AuthzStatusExpired = "expired"
)

const (
	ChallengeStatusPending    = "pending"
	ChallengeStatusProcessing = "processing"
	ChallengeStatusValid      = "valid"
	ChallengeStatusInvalid    = "invalid"
)

const (
	ChallengeTypeDeviceAttest01 = "device-attest-01"
)

type FinalizeRequest struct {
	CSR string `json:"csr"`
}

type CertificateIssuer interface {
	// The deviceInfos slice contains attestation-derived device information.
	IssueCertificate(ctx context.Context, csr *x509.CertificateRequest, deviceInfos []*DeviceInfo) (*Certificate, error)
}
