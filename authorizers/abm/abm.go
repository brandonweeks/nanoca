package abmauthorizer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/abm"
)

const (
	// refreshInterval is how often the ABM device list is fetched.
	refreshInterval = 15 * time.Minute

	// retryInterval is how soon a failed fetch is retried.
	retryInterval = time.Minute

	defaultMaxAge = 24 * time.Hour
)

type deviceLister interface {
	GetOrganizationDevices(ctx context.Context) ([]abm.Device, error)
	GetMDMServerSerials(ctx context.Context, serverID string) ([]string, error)
	GetDevice(ctx context.Context, serial string) (abm.Device, error)
	GetAssignedServerID(ctx context.Context, serial string) (string, error)
}

// ABMAuthorizer authorizes devices by checking if they exist in the Apple
// Business Manager organization. It checks against a device list that Run
// keeps up to date, so Run must be running for Authorize to succeed.
type ABMAuthorizer struct {
	client deviceLister
	logger *slog.Logger

	requireAssigned bool
	serverID        string
	maxAge          time.Duration

	mu        sync.RWMutex
	serials   map[string]struct{}
	fetchedAt time.Time
	fetchErr  error
	// misses holds serials that were looked up individually and not found.
	// It is cleared on every refresh, which bumps generation.
	misses     map[string]struct{}
	generation uint64
	// flights holds the individual lookups in progress, by serial.
	flights map[string]*flight
}

// flight is one individual lookup that every concurrent Authorize call for
// the same serial waits on. It runs until it finishes or until every
// caller waiting on it has left.
type flight struct {
	done    chan struct{}
	found   bool
	err     error
	waiters int
	cancel  context.CancelFunc
}

// Option configures an ABMAuthorizer.
type Option func(*ABMAuthorizer)

// WithRequireAssigned authorizes only devices that are assigned to a device
// management service.
func WithRequireAssigned() Option {
	return func(a *ABMAuthorizer) { a.requireAssigned = true }
}

// WithAssignedServer authorizes only devices assigned to the device
// management service with the given ID.
func WithAssignedServer(serverID string) Option {
	return func(a *ABMAuthorizer) { a.serverID = serverID }
}

// WithMaxAge sets how long the last fetched device list is used while
// refreshes fail. Once it is older, Authorize returns an error. The default
// is 24 hours.
func WithMaxAge(d time.Duration) Option {
	return func(a *ABMAuthorizer) { a.maxAge = d }
}

// New creates a new ABM authorizer with the given configuration. Run logs
// each failed refresh to logger.
func New(logger *slog.Logger, config *abm.Config, opts ...Option) (*ABMAuthorizer, error) {
	client, err := abm.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create ABM client: %w", err)
	}
	a := &ABMAuthorizer{client: client, logger: logger, maxAge: defaultMaxAge}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// Run fetches the device list now and then every 15 minutes, retrying
// sooner after a failure. It returns when ctx is done.
func (a *ABMAuthorizer) Run(ctx context.Context) error {
	for {
		wait := refreshInterval
		if err := a.refresh(ctx); err != nil {
			a.logger.WarnContext(ctx, "ABM device list refresh failed", "error", err)
			wait = retryInterval
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (a *ABMAuthorizer) refresh(ctx context.Context) error {
	serials, err := a.fetchSerials(ctx)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.fetchErr = err
	if err != nil {
		return err
	}
	a.serials = serials
	a.fetchedAt = time.Now()
	a.misses = make(map[string]struct{})
	a.generation++
	return nil
}

// Authorize determines if a device is authorized for certificate issuance
// by checking if the device serial number exists in the ABM organization.
// A device with no serial number, such as one whose attestation proves only
// the key, cannot be in the organization and is not authorized.
//
// A serial that is not in the device list is looked up individually, so a
// device added since the last refresh is found. A serial that is still not
// found is not looked up again until the next refresh. Concurrent calls for
// the same serial share one lookup.
func (a *ABMAuthorizer) Authorize(ctx context.Context, device *nanoca.DeviceInfo) (bool, error) {
	if device == nil {
		return false, errors.New("device info cannot be nil")
	}

	if device.PermanentIdentifier == nil || device.PermanentIdentifier.Identifier == "" {
		return false, nil
	}
	serial := device.PermanentIdentifier.Identifier

	a.mu.RLock()
	loaded := a.serials != nil
	age := time.Since(a.fetchedAt)
	fetchErr := a.fetchErr
	_, hit := a.serials[serial]
	_, missed := a.misses[serial]
	generation := a.generation
	a.mu.RUnlock()

	switch {
	case !loaded:
		return false, errors.Join(errors.New("ABM device list has not been fetched"), fetchErr)
	case age > a.maxAge:
		return false, errors.Join(fmt.Errorf("ABM device list is %s old", age.Round(time.Second)), fetchErr)
	case hit:
		return true, nil
	case missed:
		return false, nil
	}

	found, err := a.sharedLookup(ctx, serial, generation)
	if err != nil {
		return false, fmt.Errorf("failed to check device authorization with ABM: %w", err)
	}
	return found, nil
}

// sharedLookup joins the lookup in progress for serial, or starts one, and
// waits for it until ctx is done. The lookup runs under ctx's values but
// is canceled only when every caller waiting on it has left. A result is
// stored only if no refresh happened since generation was read.
func (a *ABMAuthorizer) sharedLookup(ctx context.Context, serial string, generation uint64) (bool, error) {
	a.mu.Lock()
	f, ok := a.flights[serial]
	if !ok {
		lookupCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		f = &flight{done: make(chan struct{}), cancel: cancel}
		if a.flights == nil {
			a.flights = make(map[string]*flight)
		}
		a.flights[serial] = f
		go func() {
			defer cancel()
			found, err := a.lookup(lookupCtx, serial)

			a.mu.Lock()
			defer a.mu.Unlock()
			f.found, f.err = found, err
			if a.flights[serial] == f {
				delete(a.flights, serial)
			}
			if err == nil && a.generation == generation {
				if found {
					a.serials[serial] = struct{}{}
				} else {
					a.misses[serial] = struct{}{}
				}
			}
			close(f.done)
		}()
	}
	f.waiters++
	a.mu.Unlock()

	select {
	case <-f.done:
		return f.found, f.err
	case <-ctx.Done():
		a.mu.Lock()
		defer a.mu.Unlock()
		f.waiters--
		if f.waiters == 0 && a.flights[serial] == f {
			delete(a.flights, serial)
			f.cancel()
		}
		return false, ctx.Err()
	}
}

// lookup checks a single serial against ABM with the same rules as
// fetchSerials.
func (a *ABMAuthorizer) lookup(ctx context.Context, serial string) (bool, error) {
	if a.serverID != "" {
		id, err := a.client.GetAssignedServerID(ctx, serial)
		if errors.Is(err, abm.ErrNotFound) {
			return false, nil
		}
		return id == a.serverID, err
	}

	d, err := a.client.GetDevice(ctx, serial)
	if errors.Is(err, abm.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !a.requireAssigned || d.Status == abm.DeviceStatusAssigned, nil
}

func (a *ABMAuthorizer) fetchSerials(ctx context.Context) (map[string]struct{}, error) {
	if a.serverID != "" {
		list, err := a.client.GetMDMServerSerials(ctx, a.serverID)
		if err != nil {
			return nil, err
		}
		serials := make(map[string]struct{}, len(list))
		for _, s := range list {
			serials[s] = struct{}{}
		}
		return serials, nil
	}

	devices, err := a.client.GetOrganizationDevices(ctx)
	if err != nil {
		return nil, err
	}
	serials := make(map[string]struct{}, len(devices))
	for _, d := range devices {
		if a.requireAssigned && d.Status != abm.DeviceStatusAssigned {
			continue
		}
		serials[d.SerialNumber] = struct{}{}
	}
	return serials, nil
}
