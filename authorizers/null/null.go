package nullauthorizer

import (
	"context"

	"github.com/brandonweeks/nanoca"
)

// NullAuthorizer is a null implementation that always authorizes devices
type NullAuthorizer struct{}

// New creates a new null authorizer
func New() *NullAuthorizer {
	return &NullAuthorizer{}
}

// Authorize always returns true, authorizing any device for certificate issuance
func (n *NullAuthorizer) Authorize(_ context.Context, _ *nanoca.DeviceInfo) (bool, error) {
	return true, nil
}
