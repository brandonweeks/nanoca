package nullauthorizer

import (
	"context"
	"encoding/asn1"
	"testing"

	"github.com/brandonweeks/nanoca"
)

func TestNew(t *testing.T) {
	t.Parallel()

	authorizer := New()
	if authorizer == nil {
		t.Error("New() returned nil")
	}
}

func TestNullAuthorizer_Authorize(t *testing.T) {
	t.Parallel()

	authorizer := New()
	ctx := t.Context()

	tests := []struct {
		name   string
		device *nanoca.DeviceInfo
	}{
		{
			name:   "nil device",
			device: nil,
		},
		{
			name:   "empty device",
			device: &nanoca.DeviceInfo{},
		},
		{
			name: "device with permanent identifier",
			device: &nanoca.DeviceInfo{
				PermanentIdentifier: &nanoca.PermanentIdentifier{
					Identifier: "device-123",
					Assigner:   asn1.ObjectIdentifier{1, 2, 3, 4},
				},
			},
		},
		{
			name: "device with hardware module",
			device: &nanoca.DeviceInfo{
				HardwareModule: &nanoca.HardwareModule{
					Type:  asn1.ObjectIdentifier{2, 23, 133, 1, 2},
					Value: []byte("tpm-id-123"),
				},
			},
		},
		{
			name: "device with serial number",
			device: &nanoca.DeviceInfo{
				PermanentIdentifier: &nanoca.PermanentIdentifier{
					Identifier: "SN123456",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authorized, err := authorizer.Authorize(ctx, tt.device)
			if err != nil {
				t.Errorf("Authorize() error = %v", err)
			}
			if !authorized {
				t.Error("Authorize() should always return true for null authorizer")
			}
		})
	}
}

func TestNullAuthorizer_AuthorizeWithContext(t *testing.T) {
	t.Parallel()

	authorizer := New()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	device := &nanoca.DeviceInfo{
		PermanentIdentifier: &nanoca.PermanentIdentifier{
			Identifier: "device-456",
		},
	}

	authorized, err := authorizer.Authorize(ctx, device)
	if err != nil {
		t.Errorf("Authorize() with cancelled context error = %v", err)
	}
	if !authorized {
		t.Error("Authorize() should always return true regardless of context state")
	}
}
