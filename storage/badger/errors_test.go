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
		{"SettleAuthz", func() error { return s.SettleAuthorization(ctx, &nanoca.Authorization{ID: "ghost"}) }},
		{"ReserveChallengeValidation", func() error {
			return s.ReserveChallengeValidation(ctx, "ghost", "token", time.Minute)
		}},
		{"ReleaseChallengeValidation", func() error {
			return s.ReleaseChallengeValidation(ctx, "ghost", "token")
		}},
		{"ReserveOrderFinalize", func() error {
			return s.ReserveOrderFinalize(ctx, "ghost", "token", time.Minute)
		}},
		{"ReleaseOrderFinalize", func() error {
			return s.ReleaseOrderFinalize(ctx, "ghost", "token", nanoca.OrderStatusReady)
		}},
		{"SetOrderStatus", func() error {
			return s.SetOrderStatus(ctx, "ghost", nanoca.OrderStatusPending, nanoca.OrderStatusReady)
		}},
		{"CompleteOrder", func() error {
			return s.CompleteOrder(ctx, &nanoca.Order{ID: "ghost"}, &nanoca.Certificate{ID: "ghost"}, "token")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); !errors.Is(err, nanoca.ErrNotFound) {
				t.Errorf("%s(missing) error = %v, want ErrNotFound", tt.name, err)
			}
		})
	}
}

func TestConsumeNonceErrors(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)
	ctx := t.Context()

	if _, err := s.ConsumeNonce(ctx, "ghost", time.Hour); !errors.Is(err, nanoca.ErrNotFound) {
		t.Errorf("ConsumeNonce(missing) error = %v, want ErrNotFound", err)
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
	if _, err := s.ConsumeNonce(ctx, "n1", -time.Second); !errors.Is(err, nanoca.ErrNotFound) {
		t.Errorf("ConsumeNonce(expired, again) error = %v, want ErrNotFound", err)
	}
}

func TestChallengeStatusMismatch(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)
	ctx := t.Context()

	if err := s.CreateChallenge(ctx, &nanoca.Challenge{ID: "c1", Status: nanoca.ChallengeStatusValid}); err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}
	if err := s.ReserveChallengeValidation(ctx, "c1", "token", time.Minute); !errors.Is(err, nanoca.ErrStatusMismatch) {
		t.Errorf("ReserveChallengeValidation(valid challenge) error = %v, want ErrStatusMismatch", err)
	}
}

func TestSetOrderStatus(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)
	ctx := t.Context()

	if err := s.CreateOrder(ctx, &nanoca.Order{ID: "o1", Status: nanoca.OrderStatusPending}); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}
	if err := s.SetOrderStatus(ctx, "o1", nanoca.OrderStatusPending, nanoca.OrderStatusReady); err != nil {
		t.Fatalf("SetOrderStatus() error = %v", err)
	}

	order, err := s.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if order.Status != nanoca.OrderStatusReady {
		t.Errorf("order status = %q, want %q", order.Status, nanoca.OrderStatusReady)
	}

	// The guard is what keeps a stale caller from redoing a transition
	// another request already made.
	if err := s.SetOrderStatus(ctx, "o1", nanoca.OrderStatusPending, nanoca.OrderStatusReady); !errors.Is(err, nanoca.ErrStatusMismatch) {
		t.Errorf("SetOrderStatus(ready) error = %v, want ErrStatusMismatch", err)
	}
}

func TestGetCertificateBadRaw(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)
	ctx := t.Context()

	storeCertificate(t, s, &nanoca.Certificate{ID: "o1", Raw: []byte("not-a-cert")})
	if _, err := s.GetCertificate(ctx, "o1"); err == nil {
		t.Error("GetCertificate(bad raw) error = nil, want parse error")
	}
}
