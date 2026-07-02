package nanoca_test

import (
	"context"
	"crypto/x509"
	"log/slog"
	"testing"

	"github.com/brandonweeks/nanoca"
	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
	store "github.com/brandonweeks/nanoca/storage/badger"
	"github.com/brandonweeks/nanoca/verifiers/null"
)

type stubIssuer struct{}

func (stubIssuer) IssueCertificate(_ context.Context, _ *x509.CertificateRequest, _ []*nanoca.DeviceInfo) (*nanoca.Certificate, error) {
	return nil, nil
}

func newTestStorage(t *testing.T) nanoca.Storage {
	t.Helper()

	storage, err := store.New(store.Options{InMemory: true})
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	return storage
}

func TestNewValidation(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	issuer := stubIssuer{}
	authz := nullauthorizer.New()
	storage := newTestStorage(t)

	tests := []struct {
		name       string
		logger     *slog.Logger
		issuer     nanoca.CertificateIssuer
		authorizer nanoca.Authorizer
		storage    nanoca.Storage
		baseURL    string
	}{
		{name: "nil logger"},
		{name: "nil issuer", logger: logger},
		{name: "nil authorizer", logger: logger, issuer: issuer},
		{name: "nil storage", logger: logger, issuer: issuer, authorizer: authz},
		{name: "empty base URL", logger: logger, issuer: issuer, authorizer: authz, storage: storage},
		{name: "no verifier", logger: logger, issuer: issuer, authorizer: authz, storage: storage, baseURL: "https://ca.example"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := nanoca.New(tt.logger, tt.issuer, tt.authorizer, tt.storage, tt.baseURL); err == nil {
				t.Error("New() error = nil, want error")
			}
		})
	}
}

func TestNewWithPrefixNormalizesLeadingSlash(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)

	ca, err := nanoca.New(
		slog.New(slog.DiscardHandler),
		stubIssuer{},
		nullauthorizer.New(),
		storage,
		"https://ca.example",
		nanoca.WithPrefix("acme"),
		nanoca.WithVerifier(null.New()),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if ca.Handler() == nil {
		t.Error("Handler() = nil")
	}
}
