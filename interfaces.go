package nanoca

import (
	"context"
	"time"
)

type AttestationVerifier interface {
	Format() string
	// Verify returns the device identity that the statement proves. The CA
	// authorizes the device and builds the certificate SANs from this
	// identity, and certifies only its PublicKey. A nil DeviceInfo or a nil
	// PublicKey with a nil error is a failed attestation.
	Verify(ctx context.Context, stmt AttestationStatement, challenge []byte) (*DeviceInfo, error)
}

type Authorizer interface {
	// Authorize decides whether the attested device may get a certificate.
	// The device may carry no identity when the attestation proves only
	// the key, as Apple User Enrollment attestations do. Admitting such a
	// device is the authorizer's decision; its certificate names no device.
	Authorize(ctx context.Context, device *DeviceInfo) (bool, error)
}

// IssuanceObserver handles actions after certificate issuance (logging, inventory updates, etc.)
type IssuanceObserver interface {
	OnIssuance(ctx context.Context, event *IssuanceEvent) error
}

// IssuanceEvent represents a certificate issuance event
type IssuanceEvent struct {
	Timestamp   time.Time
	DeviceInfo  *DeviceInfo
	Attestation *AttestationStatement
	Certificate *Certificate
	AccountID   string
	OrderID     string
	Metadata    map[string]any
}

// UnattestedRequest describes a device-attest-01 answer that carried no
// attestation object.
type UnattestedRequest struct {
	// Identifier is the authorization's identifier as the client ordered
	// it. Apple's client sends the payload's ClientIdentifier as a
	// permanent-identifier.
	Identifier  Identifier
	AccountID   string
	OrderID     string
	ChallengeID string
}

// UnattestedAuthorizer decides device-attest-01 answers that carry no
// attestation object. Apple's ACME client sends those whenever the device
// has no attestation to give: for a payload with Attest false, which is all
// macOS VMs and Macs without a T2 can use, and on devices that ignore
// Attest, which Apple lists as iPhone, iPad and Apple TV with an A10X
// Fusion or earlier, and T2 Macs. The client offers no other challenge
// type. Admitting these answers is server policy outside
// draft-ietf-acme-device-attest-10 Section 5; without an
// UnattestedAuthorizer, nanoca rejects them as malformed.
//
// It is only consulted for a permanent-identifier. The Authorizer is never
// called for these answers, so with this option set, any client that
// answers without an attestation is judged by the UnattestedAuthorizer
// alone, including a device that could have attested. It is the whole
// security boundary for these certificates, which certify the CSR key and
// name no device. Treat the identifier as a one-time secret, never a
// serial number.
//
// Each authorization is decided on its own, so an order with two
// identifiers spends two one-time credentials for one certificate, and an
// order refused at finalize, such as one mixing attested and unattested
// authorizations, has already spent its credentials.
//
// It may be called again for the same ChallengeID, when a retry reclaims a
// validation whose reservation lapsed, and must give the same answer: a
// one-time credential remembers which challenge consumed it. An error is a
// backend condition, not a verdict, and leaves the challenge pending.
type UnattestedAuthorizer interface {
	AuthorizeUnattested(ctx context.Context, req UnattestedRequest) (bool, error)
}
