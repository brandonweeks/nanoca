package abmauthorizer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/abm"
)

type fakeLister struct {
	calls   int
	devices []abm.Device
	err     error
}

func (f *fakeLister) GetOrganizationDevices(context.Context) ([]abm.Device, error) {
	f.calls++
	return f.devices, f.err
}

func serialDevice(serial string) *nanoca.DeviceInfo {
	return &nanoca.DeviceInfo{PermanentIdentifier: &nanoca.PermanentIdentifier{Identifier: serial}}
}

func TestAuthorizeUsesCachedSerials(t *testing.T) {
	t.Parallel()

	lister := &fakeLister{devices: []abm.Device{{SerialNumber: "A"}, {SerialNumber: "B"}}}
	a := &ABMAuthorizer{client: lister}

	for _, tt := range []struct {
		serial string
		want   bool
	}{{"A", true}, {"B", true}, {"C", false}, {"A", true}} {
		got, err := a.Authorize(t.Context(), serialDevice(tt.serial))
		if err != nil {
			t.Fatalf("Authorize(%s) error = %v", tt.serial, err)
		}
		if got != tt.want {
			t.Errorf("Authorize(%s) = %v, want %v", tt.serial, got, tt.want)
		}
	}
	if lister.calls != 1 {
		t.Errorf("GetOrganizationDevices calls = %d, want 1", lister.calls)
	}
}

func TestAuthorizeRefreshesStaleCache(t *testing.T) {
	t.Parallel()

	lister := &fakeLister{devices: []abm.Device{{SerialNumber: "A"}}}
	a := &ABMAuthorizer{client: lister}

	if got, _ := a.Authorize(t.Context(), serialDevice("B")); got {
		t.Fatal("Authorize(B) = true before B was added")
	}

	lister.devices = append(lister.devices, abm.Device{SerialNumber: "B"})
	a.fetchedAt = time.Now().Add(-2 * refreshInterval)

	got, err := a.Authorize(t.Context(), serialDevice("B"))
	if err != nil {
		t.Fatalf("Authorize(B) error = %v", err)
	}
	if !got {
		t.Error("Authorize(B) = false after refresh, want true")
	}
	if lister.calls != 2 {
		t.Errorf("GetOrganizationDevices calls = %d, want 2", lister.calls)
	}
}

func TestAuthorizeKeepsCacheOnRefreshError(t *testing.T) {
	t.Parallel()

	lister := &fakeLister{devices: []abm.Device{{SerialNumber: "A"}}}
	a := &ABMAuthorizer{client: lister}

	if _, err := a.Authorize(t.Context(), serialDevice("A")); err != nil {
		t.Fatalf("Authorize(A) error = %v", err)
	}

	lister.err = errors.New("api down")
	a.fetchedAt = time.Now().Add(-2 * refreshInterval)

	if _, err := a.Authorize(t.Context(), serialDevice("A")); err == nil {
		t.Fatal("Authorize(A) error = nil during outage, want error")
	}

	lister.err = nil
	if got, err := a.Authorize(t.Context(), serialDevice("A")); err != nil || !got {
		t.Errorf("Authorize(A) after outage = %v, %v, want true, nil", got, err)
	}
}
