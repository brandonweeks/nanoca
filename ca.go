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

	baseURL     string
	prefix      string
	nonceExpiry time.Duration

	storage Storage
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
		// Ensure prefix starts with '/' if non-empty
		if prefix != "" && !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		ca.prefix = prefix
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
		storage:           storage,
		baseURL:           baseURL,
		nonceExpiry:       1 * time.Hour, // default
		observers:         make([]IssuanceObserver, 0),
		verifiers:         make(map[string]AttestationVerifier),
	}

	for _, opt := range opts {
		opt(ca)
	}

	if len(ca.verifiers) == 0 {
		return nil, errors.New("at least one attestation verifier must be registered")
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

	if err := ca.storage.CreateNonce(ctx, nonceObj); err != nil {
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
