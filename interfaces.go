package nanoca

import (
	"context"
	"time"
)

type AttestationVerifier interface {
	Format() string
	// Verify returns the device identity the statement proves; the identity
	// is what authorization and the certificate's SANs are built from, so a
	// nil DeviceInfo with a nil error is treated as a failed attestation.
	Verify(ctx context.Context, stmt AttestationStatement, challenge []byte) (*DeviceInfo, error)
}

type Authorizer interface {
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
