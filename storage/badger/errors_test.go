package badger

import (
	"errors"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
)

func newTestStore(t *testing.T) *Storage {
	t.Helper()
	s, err := New(Options{InMemory: true})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestNewRequiresPath(t *testing.T) {
	t.Parallel()

	if _, err := New(Options{}); err == nil {
		t.Error("New(empty options) error = nil, want error")
	}
}

func TestNotFoundErrors(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)
	ctx := t.Context()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"GetAccount", func() error { _, err := s.GetAccount(ctx, "ghost"); return err }},
		{"GetAccountByKey", func() error { _, err := s.GetAccountByKey(ctx, "ghost"); return err }},
		{"GetOrder", func() error { _, err := s.GetOrder(ctx, "ghost"); return err }},
		{"GetAuthorization", func() error { _, err := s.GetAuthorization(ctx, "ghost"); return err }},
		{"GetChallenge", func() error { _, err := s.GetChallenge(ctx, "ghost"); return err }},
		{"GetCertificate", func() error { _, err := s.GetCertificate(ctx, "ghost"); return err }},
		{"UpdateAccount", func() error { return s.UpdateAccount(ctx, &nanoca.Account{ID: "ghost"}) }},
		{"UpdateOrder", func() error { return s.UpdateOrder(ctx, &nanoca.Order{ID: "ghost"}) }},
		{"UpdateAuthz", func() error { return s.UpdateAuthorization(ctx, &nanoca.Authorization{ID: "ghost"}) }},
		{"SetProcessing", func() error { return s.SetChallengeProcessing(ctx, "ghost") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err == nil {
				t.Errorf("%s(missing) error = nil, want not-found error", tt.name)
			}
		})
	}
}

func TestConsumeNonceErrors(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)
	ctx := t.Context()

	if _, err := s.ConsumeNonce(ctx, "ghost", time.Hour); !errors.Is(err, nanoca.ErrNonceNotFound) {
		t.Errorf("ConsumeNonce(missing) error = %v, want ErrNonceNotFound", err)
	}

	if err := s.CreateNonce(ctx, &nanoca.Nonce{Value: "n1", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateNonce() error = %v", err)
	}
	// A negative expiry window makes the just-created nonce already expired.
	if _, err := s.ConsumeNonce(ctx, "n1", -time.Second); !errors.Is(err, nanoca.ErrNonceExpired) {
		t.Errorf("ConsumeNonce(expired) error = %v, want ErrNonceExpired", err)
	}
	// Consuming an expired nonce must still remove it, or expired nonces
	// accumulate forever (nonce keys carry no TTL).
	if _, err := s.ConsumeNonce(ctx, "n1", -time.Second); !errors.Is(err, nanoca.ErrNonceNotFound) {
		t.Errorf("ConsumeNonce(expired, again) error = %v, want ErrNonceNotFound", err)
	}
}

func TestChallengeStatusMismatch(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)
	ctx := t.Context()

	if err := s.CreateChallenge(ctx, &nanoca.Challenge{ID: "c1", Status: nanoca.ChallengeStatusValid}); err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}
	if err := s.SetChallengeProcessing(ctx, "c1"); err == nil {
		t.Error("SetChallengeProcessing(valid challenge) error = nil, want status mismatch")
	}
}

func TestGetCertificateBadRaw(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)
	ctx := t.Context()

	if err := s.CreateCertificate(ctx, &nanoca.Certificate{SerialNumber: "s1", Raw: []byte("not-a-cert")}); err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	if _, err := s.GetCertificate(ctx, "s1"); err == nil {
		t.Error("GetCertificate(bad raw) error = nil, want parse error")
	}
}
