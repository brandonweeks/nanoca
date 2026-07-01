package stderr_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/observers/stderr"
)

func TestObserverOnIssuance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		device     *nanoca.DeviceInfo
		wantDevice string
	}{
		{
			name:       "nil device info",
			device:     nil,
			wantDevice: "unknown",
		},
		{
			name:       "nil permanent identifier",
			device:     &nanoca.DeviceInfo{},
			wantDevice: "unknown",
		},
		{
			name: "with permanent identifier",
			device: &nanoca.DeviceInfo{
				PermanentIdentifier: &nanoca.PermanentIdentifier{Identifier: "ABC123"},
			},
			wantDevice: "ABC123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			observer := stderr.New(slog.New(slog.NewTextHandler(&buf, nil)))

			event := &nanoca.IssuanceEvent{
				DeviceInfo:  tt.device,
				Certificate: &nanoca.Certificate{SerialNumber: "42"},
			}
			if err := observer.OnIssuance(t.Context(), event); err != nil {
				t.Fatalf("OnIssuance() error = %v", err)
			}

			if got := buf.String(); !strings.Contains(got, "device_id="+tt.wantDevice) {
				t.Errorf("log output = %q, want device_id=%s", got, tt.wantDevice)
			}
		})
	}
}
