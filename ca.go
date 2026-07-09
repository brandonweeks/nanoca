package nanoca

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"
)

type CA struct {
	logger            *slog.Logger
	certificateIssuer CertificateIssuer
	authorizer        Authorizer
	observers         []IssuanceObserver
	verifiers         map[string]AttestationVerifier

	baseURL          string
	prefix           string
	nonceExpiry      time.Duration
	orderExpiry      time.Duration
	authzExpiry      time.Duration
	reservationLease time.Duration

	// storage wraps the configured backend with the reservation and
	// status-transition machine; handlers never touch the backend directly.
	storage *storageMachine
}

type Option func(*CA)

func WithObserver(obs IssuanceObserver) Option {
	return func(ca *CA) {
		ca.observers = append(ca.observers, obs)
	}
}

func WithVerifier(v AttestationVerifier) Option {
	return func(ca *CA) {
		format := v.Format()
		if _, exists := ca.verifiers[format]; exists {
			panic(fmt.Sprintf("attestation verifier for format %q already registered", format))
		}
		ca.verifiers[format] = v
	}
}

func WithPrefix(prefix string) Option {
	return func(ca *CA) {
		if prefix != "" && !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		ca.prefix = prefix
	}
}

// WithReservationLease sets how long a finalize or challenge-validation
// reservation is honored before another request may reclaim it. It bounds
// how long a crashed instance can hold an order or challenge in processing,
// and must exceed the worst-case verifier, authorizer, and issuer latency,
// plus any wall-clock skew between CA hosts sharing the store: a reader
// whose clock runs ahead sees the lease shortened by the skew. The default
// is one minute.
func WithReservationLease(d time.Duration) Option {
	return func(ca *CA) {
		ca.reservationLease = d
	}
}

func New(logger *slog.Logger, issuer CertificateIssuer, authorizer Authorizer, storage Storage, baseURL string, opts ...Option) (*CA, error) {
	if logger == nil {
		return nil, errors.New("logger is required")
	}

	if issuer == nil {
		return nil, errors.New("certificate issuer is required")
	}

	if authorizer == nil {
		return nil, errors.New("authorizer is required")
	}

	if storage == nil {
		return nil, errors.New("storage backend is required")
	}

	if baseURL == "" {
		return nil, errors.New("base URL is required")
	}

	ca := &CA{
		logger:            logger,
		certificateIssuer: issuer,
		authorizer:        authorizer,
		storage:           newStorageMachine(storage),
		baseURL:           baseURL,
		nonceExpiry:       time.Hour,
		orderExpiry:       24 * time.Hour,
		authzExpiry:       24 * time.Hour,
		reservationLease:  time.Minute,
		verifiers:         make(map[string]AttestationVerifier),
	}

	for _, opt := range opts {
		opt(ca)
	}

	if len(ca.verifiers) == 0 {
		return nil, errors.New("at least one attestation verifier must be registered")
	}

	// A nonpositive lease makes every reservation expired at birth, so
	// concurrent finalizes would each reclaim the other's and both sign.
	if ca.reservationLease <= 0 {
		return nil, errors.New("reservation lease must be positive")
	}

	return ca, nil
}

func (ca *CA) Handler() http.Handler {
	mux := http.NewServeMux()

	prefix := ca.prefix
	mux.HandleFunc(prefix+"/directory", ca.handleDirectory)
	mux.HandleFunc(prefix+"/new-nonce", ca.handleNewNonce)
	mux.HandleFunc(prefix+"/new-account", ca.handleNewAccount)
	mux.HandleFunc(prefix+"/new-order", ca.handleNewOrder)
	mux.HandleFunc(prefix+"/order/", ca.handleOrder)
	mux.HandleFunc(prefix+"/authz/", ca.handleAuthorization)
	mux.HandleFunc(prefix+"/challenge/", ca.handleChallenge)
	mux.HandleFunc(prefix+"/certificate/", ca.handleCertificate)

	return mux
}

func (ca *CA) Close() error {
	return ca.storage.Close()
}

func (ca *CA) generateNonce(ctx context.Context) (string, error) {
	nonce := randomID(16)

	nonceObj := &Nonce{
		Value:     nonce,
		CreatedAt: time.Now(),
	}

	if err := ca.storage.CreateNonce(ctx, nonceObj, ca.nonceExpiry); err != nil {
		return "", fmt.Errorf("failed to store nonce: %w", err)
	}

	return nonce, nil
}

func (ca *CA) url(urlPath string) string {
	if ca.prefix != "" {
		urlPath = path.Join(ca.prefix, urlPath)
	}
	return ca.baseURL + urlPath
}

func (ca *CA) extractPathSegment(urlPath, segment string) string {
	if ca.prefix != "" && strings.HasPrefix(urlPath, ca.prefix) {
		urlPath = strings.TrimPrefix(urlPath, ca.prefix)
	}
	return strings.TrimPrefix(urlPath, segment)
}
