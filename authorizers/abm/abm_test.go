package abmauthorizer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/abm"
	abmauthorizer "github.com/brandonweeks/nanoca/authorizers/abm"
)

func TestNew(t *testing.T) {
	t.Parallel()

	if _, err := abmauthorizer.New(t.Context(), nil); err == nil {
		t.Error("New(nil config) error = nil, want error")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	cfg := &abm.Config{JWTConfig: &abm.JWTConfig{ClientID: "id", PrivateKey: key}}
	if _, err := abmauthorizer.New(t.Context(), cfg); err != nil {
		t.Errorf("New() error = %v, want success", err)
	}
}

func TestAuthorizeRejectsBeforeNetwork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		device *nanoca.DeviceInfo
	}{
		{
			name:   "nil device",
			device: nil,
		},
		{
			name:   "nil permanent identifier",
			device: &nanoca.DeviceInfo{},
		},
		{
			name: "empty serial number",
			device: &nanoca.DeviceInfo{
				PermanentIdentifier: &nanoca.PermanentIdentifier{Identifier: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authorized, err := (&abmauthorizer.ABMAuthorizer{}).Authorize(t.Context(), tt.device)
			if err == nil {
				t.Fatal("Authorize() error = nil, want error")
			}
			if authorized {
				t.Error("Authorize() = true, want false")
			}
		})
	}
}
