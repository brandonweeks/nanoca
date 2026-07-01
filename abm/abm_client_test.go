package abm_test

import (
	"testing"

	"github.com/brandonweeks/nanoca/abm"
)

func TestNewValidation(t *testing.T) {
	t.Parallel()

	if _, err := abm.New(t.Context(), nil); err == nil {
		t.Error("New(nil) error = nil, want error")
	}
	if _, err := abm.New(t.Context(), &abm.Config{}); err == nil {
		t.Error("New(config without JWTConfig) error = nil, want error")
	}
}

func TestNewAndCreateJWTClient(t *testing.T) {
	t.Parallel()

	cfg := &abm.Config{JWTConfig: &abm.JWTConfig{
		ClientID:   "client-id",
		PrivateKey: newKey(t),
		KeyID:      "key-id",
	}}

	if _, err := abm.New(t.Context(), cfg); err != nil {
		t.Fatalf("New() error = %v", err)
	}

	client, err := abm.CreateJWTClient(t.Context(), cfg.JWTConfig)
	if err != nil {
		t.Fatalf("CreateJWTClient() error = %v", err)
	}
	if client == nil {
		t.Error("CreateJWTClient() returned nil client")
	}
}
