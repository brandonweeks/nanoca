package nanoca

import (
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
	// ACME draft specification identifiers - these map to ACME identifier types
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

type Certificate struct {
	*x509.Certificate `json:"-"` // Exclude from JSON serialization
	Raw               []byte     `json:"raw"`
	SerialNumber      string     `json:"serialNumber"`
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
	ID                   string           `json:"id"`                 // Include in storage
	Key                  *jose.JSONWebKey `json:"key,omitempty"`      // Include in storage
	KeyBytes             []byte           `json:"keyBytes,omitempty"` // Include in storage
	Status               string           `json:"status"`
	Contact              []string         `json:"contact,omitempty"`
	TermsOfServiceAgreed bool             `json:"termsOfServiceAgreed,omitempty"`
	Orders               string           `json:"orders,omitempty"`
	CreatedAt            time.Time        `json:"createdAt"` // Include in storage
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
	// Device attestation specific fields
	Attestation map[string]any `json:"attestation,omitempty"`
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
	IssueCertificate(csr *x509.CertificateRequest, deviceInfos []*DeviceInfo) (*Certificate, error)
}
