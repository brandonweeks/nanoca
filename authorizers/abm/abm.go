package abmauthorizer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/abm"
)

// refreshInterval is how often the ABM device list is fetched.
const refreshInterval = 15 * time.Minute

type deviceLister interface {
	GetOrganizationDevices(ctx context.Context) ([]abm.Device, error)
}

// ABMAuthorizer authorizes devices by checking if they exist in the Apple Business Manager organization
type ABMAuthorizer struct {
	client deviceLister

	mu        sync.Mutex
	serials   map[string]struct{}
	fetchedAt time.Time
}

// New creates a new ABM authorizer with the given configuration
func New(config *abm.Config) (*ABMAuthorizer, error) {
	client, err := abm.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create ABM client: %w", err)
	}
	return &ABMAuthorizer{
		client: client,
	}, nil
}

// Authorize determines if a device is authorized for certificate issuance
// by checking if the device serial number exists in the ABM organization.
// A device with no serial number, such as one whose attestation proves only
// the key, cannot be in the organization and is not authorized.
func (a *ABMAuthorizer) Authorize(ctx context.Context, device *nanoca.DeviceInfo) (bool, error) {
	if device == nil {
		return false, errors.New("device info cannot be nil")
	}

	if device.PermanentIdentifier == nil || device.PermanentIdentifier.Identifier == "" {
		return false, nil
	}
	serialNumber := device.PermanentIdentifier.Identifier

	serials, err := a.organizationSerials(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check device authorization with ABM: %w", err)
	}

	_, ok := serials[serialNumber]
	return ok, nil
}

// organizationSerials returns the cached serial set, refreshing it from ABM
// when it is older than refreshInterval. The lock is held across the fetch
// so concurrent callers share one refresh.
func (a *ABMAuthorizer) organizationSerials(ctx context.Context) (map[string]struct{}, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.serials != nil && time.Since(a.fetchedAt) < refreshInterval {
		return a.serials, nil
	}

	devices, err := a.client.GetOrganizationDevices(ctx)
	if err != nil {
		return nil, err
	}
	serials := make(map[string]struct{}, len(devices))
	for _, d := range devices {
		serials[d.SerialNumber] = struct{}{}
	}
	a.serials = serials
	a.fetchedAt = time.Now()
	return serials, nil
}
