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
	Verify(ctx context.Context, stmt AttestationStatement, binding ChallengeBinding) (*DeviceInfo, error)
}

// ChallengeBinding carries the values an attestation statement can be bound
// to, so each format checks the one its clients sign over.
// draft-ietf-acme-device-attest-10 Section 5 binds attToBeSigned to the key
// authorization, which covers the account key as well; Apple's Managed Device
// Attestation signs over the token alone.
type ChallengeBinding struct {
	// Token is the challenge token, RFC 8555 Section 8.3.
	Token string
	// KeyAuthorization is built from the token and the account key
	// thumbprint, RFC 8555 Section 8.1.
	KeyAuthorization string
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
