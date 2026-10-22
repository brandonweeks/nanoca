package abmauthorizer

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/abm"
)

type fakeLister struct {
	mu        sync.Mutex
	devices   []abm.Device
	servers   map[string][]string
	listErr   error
	lookupErr error
	lookups   int
	onList    func()
	onLookup  func(context.Context)
}

func (f *fakeLister) GetOrganizationDevices(context.Context) ([]abm.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.onList != nil {
		f.onList()
	}
	return f.devices, f.listErr
}

func (f *fakeLister) GetMDMServerSerials(_ context.Context, serverID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.servers[serverID], f.listErr
}

func (f *fakeLister) GetDevice(ctx context.Context, serial string) (abm.Device, error) {
	f.lookup(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lookupErr != nil {
		return abm.Device{}, f.lookupErr
	}
	for _, d := range f.devices {
		if d.SerialNumber == serial {
			return d, nil
		}
	}
	return abm.Device{}, abm.ErrNotFound
}

func (f *fakeLister) GetAssignedServerID(ctx context.Context, serial string) (string, error) {
	f.lookup(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lookupErr != nil {
		return "", f.lookupErr
	}
	for id, serials := range f.servers {
		if slices.Contains(serials, serial) {
			return id, nil
		}
	}
	return "", abm.ErrNotFound
}

// lookup runs onLookup without holding mu, so the hook can call back into
// the authorizer.
func (f *fakeLister) lookup(ctx context.Context) {
	f.mu.Lock()
	f.lookups++
	hook := f.onLookup
	f.mu.Unlock()
	if hook != nil {
		hook(ctx)
	}
}

func (f *fakeLister) lookupCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lookups
}

func serialDevice(serial string) *nanoca.DeviceInfo {
	return &nanoca.DeviceInfo{PermanentIdentifier: &nanoca.PermanentIdentifier{Identifier: serial}}
}

func newAuthorizer(t *testing.T, lister *fakeLister, opts ...Option) *ABMAuthorizer {
	t.Helper()
	a := &ABMAuthorizer{client: lister, maxAge: defaultMaxAge}
	for _, opt := range opts {
		opt(a)
	}
	if err := a.refresh(t.Context()); err != nil {
		t.Fatalf("refresh() error = %v", err)
	}
	return a
}

func authorize(t *testing.T, a *ABMAuthorizer, serial string) bool {
	t.Helper()
	got, err := a.Authorize(t.Context(), serialDevice(serial))
	if err != nil {
		t.Fatalf("Authorize(%s) error = %v", serial, err)
	}
	return got
}

func TestAuthorizeBeforeFirstFetch(t *testing.T) {
	t.Parallel()

	lister := &fakeLister{listErr: errors.New("api down")}
	a := &ABMAuthorizer{client: lister, maxAge: defaultMaxAge}
	if _, err := a.Authorize(t.Context(), serialDevice("A")); err == nil {
		t.Fatal("Authorize() error = nil before any fetch, want error")
	}

	_ = a.refresh(t.Context())
	_, err := a.Authorize(t.Context(), serialDevice("A"))
	if err == nil || !errors.Is(err, lister.listErr) {
		t.Errorf("Authorize() error = %v, want it to wrap the fetch error", err)
	}
}

func TestAuthorizeUsesFetchedList(t *testing.T) {
	t.Parallel()

	lister := &fakeLister{devices: []abm.Device{{SerialNumber: "A"}, {SerialNumber: "B"}}}
	a := newAuthorizer(t, lister)

	if !authorize(t, a, "A") || !authorize(t, a, "B") {
		t.Error("Authorize() = false for a listed device")
	}
	if n := lister.lookupCount(); n != 0 {
		t.Errorf("lookups = %d, want 0", n)
	}
}

func TestAuthorizeLooksUpNewDevice(t *testing.T) {
	t.Parallel()

	lister := &fakeLister{devices: []abm.Device{{SerialNumber: "A"}}}
	a := newAuthorizer(t, lister)

	lister.mu.Lock()
	lister.devices = append(lister.devices, abm.Device{SerialNumber: "B"})
	lister.mu.Unlock()

	for range 2 {
		if !authorize(t, a, "B") {
			t.Error("Authorize(B) = false, want true from lookup")
		}
	}
	if n := lister.lookupCount(); n != 1 {
		t.Errorf("lookups = %d, want 1", n)
	}
}

func TestAuthorizeStoresMissUntilRefresh(t *testing.T) {
	t.Parallel()

	lister := &fakeLister{devices: []abm.Device{{SerialNumber: "A"}}}
	a := newAuthorizer(t, lister)

	for range 2 {
		if authorize(t, a, "C") {
			t.Error("Authorize(C) = true, want false")
		}
	}
	if n := lister.lookupCount(); n != 1 {
		t.Errorf("lookups = %d, want 1", n)
	}

	if err := a.refresh(t.Context()); err != nil {
		t.Fatalf("refresh() error = %v", err)
	}
	authorize(t, a, "C")
	if n := lister.lookupCount(); n != 2 {
		t.Errorf("lookups after refresh = %d, want 2", n)
	}
}

func TestAuthorizeDropsMissFromBeforeRefresh(t *testing.T) {
	t.Parallel()

	lister := &fakeLister{devices: []abm.Device{{SerialNumber: "A"}}}
	a := newAuthorizer(t, lister)
	lister.onLookup = func(ctx context.Context) {
		lister.mu.Lock()
		lister.onLookup = nil
		lister.mu.Unlock()
		if err := a.refresh(ctx); err != nil {
			t.Errorf("refresh() error = %v", err)
		}
	}

	authorize(t, a, "C")
	authorize(t, a, "C")
	if n := lister.lookupCount(); n != 2 {
		t.Errorf("lookups = %d, want 2", n)
	}
}

func TestAuthorizeLookupErrorIsNotStored(t *testing.T) {
	t.Parallel()

	lister := &fakeLister{devices: []abm.Device{{SerialNumber: "A"}}, lookupErr: errors.New("api down")}
	a := newAuthorizer(t, lister)

	if _, err := a.Authorize(t.Context(), serialDevice("C")); err == nil {
		t.Fatal("Authorize(C) error = nil, want lookup error")
	}
	lister.mu.Lock()
	lister.lookupErr = nil
	lister.mu.Unlock()
	authorize(t, a, "C")
	if n := lister.lookupCount(); n != 2 {
		t.Errorf("lookups = %d, want 2", n)
	}
}

func TestAuthorizeServesStaleListUntilMaxAge(t *testing.T) {
	t.Parallel()

	lister := &fakeLister{devices: []abm.Device{{SerialNumber: "A"}}}
	a := newAuthorizer(t, lister, WithMaxAge(time.Hour))

	lister.listErr = errors.New("api down")
	if err := a.refresh(t.Context()); err == nil {
		t.Fatal("refresh() error = nil, want error")
	}
	if !authorize(t, a, "A") {
		t.Error("Authorize(A) = false during outage, want last fetched list")
	}

	a.mu.Lock()
	a.fetchedAt = time.Now().Add(-2 * time.Hour)
	a.mu.Unlock()
	_, err := a.Authorize(t.Context(), serialDevice("A"))
	if err == nil || !errors.Is(err, lister.listErr) {
		t.Errorf("Authorize(A) error = %v, want stale list error wrapping the fetch error", err)
	}
}

func TestAuthorizeAssignment(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		opts []Option
		want map[string]bool
	}{
		{"any", nil, map[string]bool{"A": true, "B": true, "C": true, "D": false}},
		{"require assigned", []Option{WithRequireAssigned()}, map[string]bool{"A": true, "B": false, "C": true, "D": false}},
		{"assigned server", []Option{WithAssignedServer("ours")}, map[string]bool{"A": true, "B": false, "C": false, "D": false}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lister := &fakeLister{
				devices: []abm.Device{
					{SerialNumber: "A", Status: abm.DeviceStatusAssigned},
					{SerialNumber: "B", Status: abm.DeviceStatusUnassigned},
				},
				servers: map[string][]string{"ours": {"A"}},
			}
			a := newAuthorizer(t, lister, tt.opts...)

			// C is added after the fetch and is only found by lookup.
			lister.mu.Lock()
			lister.devices = append(lister.devices, abm.Device{SerialNumber: "C", Status: abm.DeviceStatusAssigned})
			lister.servers["theirs"] = []string{"C"}
			lister.mu.Unlock()

			for serial, want := range tt.want {
				if got := authorize(t, a, serial); got != want {
					t.Errorf("Authorize(%s) = %v, want %v", serial, got, want)
				}
			}
		})
	}
}

func TestRunFetchesUntilCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	lister := &fakeLister{devices: []abm.Device{{SerialNumber: "A"}}, onList: cancel}
	a := &ABMAuthorizer{client: lister, maxAge: defaultMaxAge}

	if err := a.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	if !authorize(t, a, "A") {
		t.Error("Authorize(A) = false after Run fetched the list")
	}
}

func TestRunLogsRefreshError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	lister := &fakeLister{listErr: errors.New("api down"), onList: cancel}
	var logs bytes.Buffer
	a := &ABMAuthorizer{client: lister, logger: slog.New(slog.NewTextHandler(&logs, nil)), maxAge: defaultMaxAge}

	if err := a.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "api down") {
		t.Errorf("logs = %q, want a warning carrying the fetch error", logs.String())
	}
}

func TestAuthorizeSharesConcurrentLookups(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lister := &fakeLister{devices: []abm.Device{{SerialNumber: "A"}}}
		a := newAuthorizer(t, lister)
		release := make(chan struct{})
		lister.onLookup = func(context.Context) { <-release }

		lister.mu.Lock()
		lister.devices = append(lister.devices, abm.Device{SerialNumber: "B"})
		lister.mu.Unlock()

		var wg sync.WaitGroup
		for range 3 {
			wg.Go(func() {
				if !authorize(t, a, "B") {
					t.Error("Authorize(B) = false, want true from lookup")
				}
			})
		}
		synctest.Wait()
		close(release)
		wg.Wait()

		if n := lister.lookupCount(); n != 1 {
			t.Errorf("lookups = %d, want 1", n)
		}
	})
}

func TestAuthorizeSharedLookupOutlivesFirstCaller(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lister := &fakeLister{devices: []abm.Device{{SerialNumber: "A"}}}
		a := newAuthorizer(t, lister)
		release := make(chan struct{})
		lister.onLookup = func(context.Context) { <-release }

		lister.mu.Lock()
		lister.devices = append(lister.devices, abm.Device{SerialNumber: "B"})
		lister.mu.Unlock()

		first, cancel := context.WithCancel(t.Context())
		firstErr := make(chan error, 1)
		go func() {
			_, err := a.Authorize(first, serialDevice("B"))
			firstErr <- err
		}()
		synctest.Wait()
		second := make(chan bool, 1)
		go func() { second <- authorize(t, a, "B") }()
		synctest.Wait()

		cancel()
		if err := <-firstErr; !errors.Is(err, context.Canceled) {
			t.Errorf("first Authorize(B) error = %v, want context.Canceled", err)
		}
		close(release)
		if !<-second {
			t.Error("second Authorize(B) = false, want true from the shared lookup")
		}
		if n := lister.lookupCount(); n != 1 {
			t.Errorf("lookups = %d, want 1", n)
		}
	})
}

func TestAuthorizeCancelsLookupWhenEveryCallerLeaves(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lister := &fakeLister{devices: []abm.Device{{SerialNumber: "A"}}}
		a := newAuthorizer(t, lister)
		lookupDone := make(chan error, 1)
		lister.onLookup = func(ctx context.Context) {
			<-ctx.Done()
			lookupDone <- ctx.Err()
		}

		ctx, cancel := context.WithCancel(t.Context())
		authorized := make(chan error, 1)
		go func() {
			_, err := a.Authorize(ctx, serialDevice("B"))
			authorized <- err
		}()
		synctest.Wait()
		cancel()

		if err := <-authorized; !errors.Is(err, context.Canceled) {
			t.Errorf("Authorize(B) error = %v, want context.Canceled", err)
		}
		if err := <-lookupDone; !errors.Is(err, context.Canceled) {
			t.Errorf("lookup context error = %v, want context.Canceled", err)
		}
	})
}
