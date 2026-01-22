package abmauthorizer

import (
	"context"
	"errors"
	"fmt"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/abm"
)

// ABMAuthorizer authorizes devices by checking if they exist in the Apple Business Manager organization
type ABMAuthorizer struct {
	client *abm.Client
}

// New creates a new ABM authorizer with the given configuration
func New(ctx context.Context, config *abm.Config) (*ABMAuthorizer, error) {
	client, err := abm.New(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create ABM client: %w", err)
	}
	return &ABMAuthorizer{
		client: client,
	}, nil
}

// Authorize determines if a device is authorized for certificate issuance
// by checking if the device serial number exists in the ABM organization
func (a *ABMAuthorizer) Authorize(ctx context.Context, device *nanoca.DeviceInfo) (bool, error) {
	if device == nil {
		return false, errors.New("device info cannot be nil")
	}

	var serialNumber string
	if device.PermanentIdentifier != nil {
		serialNumber = device.PermanentIdentifier.Identifier
	}
	if serialNumber == "" {
		return false, errors.New("device has no permanent identifier (serial number)")
	}

	devices, err := a.client.GetOrganizationDevices(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check device authorization with ABM: %w", err)
	}

	for _, device := range devices {
		if device.SerialNumber == serialNumber {
			return true, nil
		}
	}

	return false, nil
}
