package abmauthorizer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"testing"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/abm"
	abmauthorizer "github.com/brandonweeks/nanoca/authorizers/abm"
)

func TestNew(t *testing.T) {
	t.Parallel()

	if _, err := abmauthorizer.New(slog.New(slog.DiscardHandler), nil); err == nil {
		t.Error("New(nil config) error = nil, want error")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	cfg := &abm.Config{
		BaseURL: abm.BusinessBaseURL,
		Token: abm.TokenConfig{
			ClientID:   "id",
			KeyID:      "key-id",
			PrivateKey: key,
			TokenURL:   abm.BusinessTokenURL,
			Scope:      abm.BusinessScope,
		},
	}
	if _, err := abmauthorizer.New(slog.New(slog.DiscardHandler), cfg); err != nil {
		t.Errorf("New() error = %v, want success", err)
	}
}

func TestAuthorizeRejectsBeforeNetwork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		device  *nanoca.DeviceInfo
		wantErr bool
	}{
		{
			name:    "nil device",
			device:  nil,
			wantErr: true,
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
			if (err != nil) != tt.wantErr {
				t.Fatalf("Authorize() error = %v, wantErr %v", err, tt.wantErr)
			}
			if authorized {
				t.Error("Authorize() = true, want false")
			}
		})
	}
}
