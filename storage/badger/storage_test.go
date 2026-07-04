package badger

import (
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{
			name: "in-memory storage",
			opts: Options{InMemory: true},
		},
		{
			name:    "no path for persistent storage",
			opts:    Options{Path: "", InMemory: false},
			wantErr: true,
		},
		{
			name: "with path for persistent storage",
			opts: Options{Path: "/tmp/test-badger", InMemory: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			storage, err := New(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if storage != nil {
				storage.Close()
			}
		})
	}
}

func newTestStorage(t *testing.T) *Storage {
	t.Helper()

	storage, err := New(Options{InMemory: true})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	t.Cleanup(func() { storage.Close() })
	return storage
}

func TestStorage_NonceOperations(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)

	ctx := t.Context()
	nonce := &nanoca.Nonce{
		Value:     "test-nonce-123",
		CreatedAt: time.Now(),
	}

	err := storage.CreateNonce(ctx, nonce)
	if err != nil {
		t.Errorf("CreateNonce() error = %v", err)
	}

	consumed, err := storage.ConsumeNonce(ctx, nonce.Value, time.Hour)
	if err != nil {
		t.Errorf("ConsumeNonce() error = %v", err)
	}
	if consumed.Value != nonce.Value {
		t.Errorf("ConsumeNonce() value = %v, want %v", consumed.Value, nonce.Value)
	}

	_, err = storage.ConsumeNonce(ctx, nonce.Value, time.Hour)
	if err == nil {
		t.Error("ConsumeNonce() should fail for already consumed nonce")
	}
	if !errors.Is(err, nanoca.ErrNotFound) {
		t.Errorf("ConsumeNonce() error = %v, want ErrNotFound", err)
	}

	expiredNonce := &nanoca.Nonce{
		Value:     "expired-nonce",
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	storage.CreateNonce(ctx, expiredNonce)

	_, err = storage.ConsumeNonce(ctx, expiredNonce.Value, time.Hour)
	if err == nil {
		t.Error("ConsumeNonce() should fail for expired nonce")
	}
	if !errors.Is(err, nanoca.ErrNonceExpired) {
		t.Errorf("ConsumeNonce() error = %v, want ErrNonceExpired", err)
	}
}

// Handlers either drop UpdateAccount errors or surface them as 500s, so
// concurrent updates to one record must not fail spuriously (e.g. with
// badger.ErrConflict from the existence check sharing the write txn).
func TestStorage_ConcurrentAccountUpdates(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	ctx := t.Context()

	if err := storage.CreateAccount(ctx, &nanoca.Account{ID: "a1"}); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() {
			for range 200 {
				if err := storage.UpdateAccount(ctx, &nanoca.Account{ID: "a1", Status: "valid"}); err != nil {
					errs <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("UpdateAccount() error = %v", err)
	}
}

func TestStorage_CreateAccountDuplicateKey(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	ctx := t.Context()

	if err := storage.CreateAccount(ctx, &nanoca.Account{ID: "first", KeyThumbprint: "thumb"}); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	err := storage.CreateAccount(ctx, &nanoca.Account{ID: "second", KeyThumbprint: "thumb"})
	if !errors.Is(err, nanoca.ErrAccountExists) {
		t.Errorf("CreateAccount() error = %v, want ErrAccountExists", err)
	}

	retrieved, err := storage.GetAccountByKey(ctx, "thumb")
	if err != nil {
		t.Fatalf("GetAccountByKey() error = %v", err)
	}
	if retrieved.ID != "first" {
		t.Errorf("GetAccountByKey() ID = %v, want first", retrieved.ID)
	}
}

func TestStorage_AccountOperations(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)

	ctx := t.Context()
	account := &nanoca.Account{
		ID:            "test-account-123",
		Contact:       []string{"mailto:test@example.com"},
		Status:        "valid",
		KeyThumbprint: "key-thumbprint-hash",
	}

	err := storage.CreateAccount(ctx, account)
	if err != nil {
		t.Errorf("CreateAccount() error = %v", err)
	}

	retrieved, err := storage.GetAccount(ctx, account.ID)
	if err != nil {
		t.Errorf("GetAccount() error = %v", err)
	}
	if retrieved.ID != account.ID {
		t.Errorf("GetAccount() ID = %v, want %v", retrieved.ID, account.ID)
	}

	retrieved, err = storage.GetAccountByKey(ctx, account.KeyThumbprint)
	if err != nil {
		t.Errorf("GetAccountByKey() error = %v", err)
	}
	if retrieved.ID != account.ID {
		t.Errorf("GetAccountByKey() ID = %v, want %v", retrieved.ID, account.ID)
	}

	account.Contact = []string{"mailto:updated@example.com"}
	err = storage.UpdateAccount(ctx, account)
	if err != nil {
		t.Errorf("UpdateAccount() error = %v", err)
	}

	retrieved, err = storage.GetAccount(ctx, account.ID)
	if err != nil {
		t.Errorf("GetAccount() after update error = %v", err)
	}
	if len(retrieved.Contact) != 1 || retrieved.Contact[0] != "mailto:updated@example.com" {
		t.Errorf("UpdateAccount() contact = %v, want [mailto:updated@example.com]", retrieved.Contact)
	}

	_, err = storage.GetAccount(ctx, "nonexistent")
	if err == nil {
		t.Error("GetAccount() should fail for nonexistent account")
	}

	nonExistent := &nanoca.Account{ID: "nonexistent"}
	err = storage.UpdateAccount(ctx, nonExistent)
	if err == nil {
		t.Error("UpdateAccount() should fail for nonexistent account")
	}
}

func TestStorage_OrderOperations(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)

	ctx := t.Context()
	expires := time.Now().Add(24 * time.Hour)
	order := &nanoca.Order{
		ID:          "test-order-123",
		AccountID:   "account-123",
		Status:      "pending",
		Expires:     &expires,
		Identifiers: []nanoca.Identifier{{Type: "permanent-identifier", Value: "device-123"}},
	}

	err := storage.CreateOrder(ctx, order)
	if err != nil {
		t.Errorf("CreateOrder() error = %v", err)
	}

	retrieved, err := storage.GetOrder(ctx, order.ID)
	if err != nil {
		t.Errorf("GetOrder() error = %v", err)
	}
	if retrieved.ID != order.ID {
		t.Errorf("GetOrder() ID = %v, want %v", retrieved.ID, order.ID)
	}

	err = storage.SetOrderStatus(ctx, order.ID, nanoca.OrderStatusPending, nanoca.OrderStatusReady)
	if err != nil {
		t.Errorf("SetOrderStatus() error = %v", err)
	}

	retrieved, err = storage.GetOrder(ctx, order.ID)
	if err != nil {
		t.Errorf("GetOrder() after update error = %v", err)
	}
	if retrieved.Status != "ready" {
		t.Errorf("SetOrderStatus() status = %v, want ready", retrieved.Status)
	}

	orders, err := storage.GetOrdersByAccount(ctx, order.AccountID)
	if err != nil {
		t.Errorf("GetOrdersByAccount() error = %v", err)
	}
	if len(orders) != 1 {
		t.Errorf("GetOrdersByAccount() length = %v, want 1", len(orders))
	}
	if orders[0].ID != order.ID {
		t.Errorf("GetOrdersByAccount() order ID = %v, want %v", orders[0].ID, order.ID)
	}

	_, err = storage.GetOrder(ctx, "nonexistent")
	if err == nil {
		t.Error("GetOrder() should fail for nonexistent order")
	}
}

func TestStorage_AuthorizationOperations(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)

	ctx := t.Context()
	authzExpires := time.Now().Add(24 * time.Hour)
	authz := &nanoca.Authorization{
		ID:         "test-authz-123",
		Status:     "pending",
		Expires:    &authzExpires,
		Identifier: nanoca.Identifier{Type: "permanent-identifier", Value: "device-123"},
	}

	err := storage.CreateAuthorization(ctx, authz)
	if err != nil {
		t.Errorf("CreateAuthorization() error = %v", err)
	}

	retrieved, err := storage.GetAuthorization(ctx, authz.ID)
	if err != nil {
		t.Errorf("GetAuthorization() error = %v", err)
	}
	if retrieved.ID != authz.ID {
		t.Errorf("GetAuthorization() ID = %v, want %v", retrieved.ID, authz.ID)
	}

	authz.Status = "valid"
	err = storage.SettleAuthorization(ctx, authz)
	if err != nil {
		t.Errorf("SettleAuthorization() error = %v", err)
	}

	retrieved, err = storage.GetAuthorization(ctx, authz.ID)
	if err != nil {
		t.Errorf("GetAuthorization() after settle error = %v", err)
	}
	if retrieved.Status != "valid" {
		t.Errorf("SettleAuthorization() status = %v, want valid", retrieved.Status)
	}

	// The guard is what keeps a recompute from stale reads from
	// overwriting a settled authorization.
	authz.Status = "invalid"
	if err := storage.SettleAuthorization(ctx, authz); !errors.Is(err, nanoca.ErrStatusMismatch) {
		t.Errorf("SettleAuthorization(settled) error = %v, want ErrStatusMismatch", err)
	}

	_, err = storage.GetAuthorization(ctx, "nonexistent")
	if err == nil {
		t.Error("GetAuthorization() should fail for nonexistent authorization")
	}

	nonExistent := &nanoca.Authorization{ID: "nonexistent"}
	err = storage.SettleAuthorization(ctx, nonExistent)
	if err == nil {
		t.Error("SettleAuthorization() should fail for nonexistent authorization")
	}
}

func TestStorage_ChallengeOperations(t *testing.T) {
	t.Parallel()

	t.Run("CreateAndGet", func(t *testing.T) {
		t.Parallel()

		storage := newTestStorage(t)

		ctx := t.Context()
		challenge := &nanoca.Challenge{
			ID:     "test-challenge-123",
			Type:   "device-attest-01",
			Status: "pending",
			Token:  "test-token",
		}

		if err := storage.CreateChallenge(ctx, challenge); err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}

		retrieved, err := storage.GetChallenge(ctx, challenge.ID)
		if err != nil {
			t.Fatalf("GetChallenge() error = %v", err)
		}
		if retrieved.ID != challenge.ID {
			t.Errorf("GetChallenge() ID = %v, want %v", retrieved.ID, challenge.ID)
		}
		if retrieved.Status != "pending" {
			t.Errorf("GetChallenge() Status = %v, want pending", retrieved.Status)
		}

		_, err = storage.GetChallenge(ctx, "nonexistent")
		if err == nil {
			t.Error("GetChallenge() should fail for nonexistent challenge")
		}
	})

	t.Run("ReserveChallengeValidation", func(t *testing.T) {
		t.Parallel()

		storage := newTestStorage(t)

		ctx := t.Context()
		challenge := &nanoca.Challenge{
			ID:     "proc-challenge",
			Type:   "device-attest-01",
			Status: "pending",
			Token:  "test-token",
		}
		if err := storage.CreateChallenge(ctx, challenge); err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}

		if err := storage.ReserveChallengeValidation(ctx, challenge.ID, "t1", time.Minute); err != nil {
			t.Fatalf("ReserveChallengeValidation() error = %v", err)
		}

		retrieved, err := storage.GetChallenge(ctx, challenge.ID)
		if err != nil {
			t.Fatalf("GetChallenge() error = %v", err)
		}
		if retrieved.Status != "processing" {
			t.Errorf("Status = %v, want processing", retrieved.Status)
		}
		if retrieved.Reservation == nil || retrieved.Reservation.Token != "t1" {
			t.Errorf("Reservation = %+v, want token t1", retrieved.Reservation)
		}

		// a live reservation refuses a second holder
		if err := storage.ReserveChallengeValidation(ctx, challenge.ID, "t2", time.Minute); !errors.Is(err, nanoca.ErrReserved) {
			t.Errorf("ReserveChallengeValidation(reserved) error = %v, want ErrReserved", err)
		}

		// a negative lease makes the reservation already expired: a retried
		// POST reclaims a validation interrupted before a terminal status
		if err := storage.ReserveChallengeValidation(ctx, challenge.ID, "t2", -time.Second); err != nil {
			t.Errorf("ReserveChallengeValidation(expired) error = %v, want success", err)
		}
		retrieved, err = storage.GetChallenge(ctx, challenge.ID)
		if err != nil {
			t.Fatalf("GetChallenge() error = %v", err)
		}
		if retrieved.Reservation == nil || retrieved.Reservation.Token != "t2" {
			t.Errorf("Reservation after reclaim = %+v, want token t2", retrieved.Reservation)
		}

		// nonexistent challenge
		if err := storage.ReserveChallengeValidation(ctx, "nonexistent", "t1", time.Minute); err == nil {
			t.Error("ReserveChallengeValidation() should fail for nonexistent challenge")
		}
	})

	t.Run("SetChallengeValid", func(t *testing.T) {
		t.Parallel()

		storage := newTestStorage(t)

		ctx := t.Context()
		challenge := &nanoca.Challenge{
			ID:     "valid-challenge",
			Type:   "device-attest-01",
			Status: "pending",
			Token:  "test-token",
		}
		if err := storage.CreateChallenge(ctx, challenge); err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}
		if err := storage.ReserveChallengeValidation(ctx, challenge.ID, "t1", time.Minute); err != nil {
			t.Fatalf("ReserveChallengeValidation() error = %v", err)
		}

		now := time.Now()
		attestation := []byte("attestation-object")

		// a stale holder's token is rejected
		if err := storage.SetChallengeValid(ctx, challenge.ID, "stale", now, attestation); !errors.Is(err, nanoca.ErrReserved) {
			t.Errorf("SetChallengeValid(stale token) error = %v, want ErrReserved", err)
		}

		if err := storage.SetChallengeValid(ctx, challenge.ID, "t1", now, attestation); err != nil {
			t.Fatalf("SetChallengeValid() error = %v", err)
		}

		retrieved, err := storage.GetChallenge(ctx, challenge.ID)
		if err != nil {
			t.Fatalf("GetChallenge() error = %v", err)
		}
		if retrieved.Status != "valid" {
			t.Errorf("Status = %v, want valid", retrieved.Status)
		}
		if retrieved.Validated == nil {
			t.Error("Validated should be set")
		}
		if retrieved.Attestation == nil {
			t.Error("Attestation should be set")
		}
		if retrieved.Error != nil {
			t.Error("Error should be nil")
		}
		if retrieved.Reservation != nil {
			t.Error("Reservation should be cleared by the terminal write")
		}

		// calling on a valid challenge should fail (expects processing)
		if err := storage.SetChallengeValid(ctx, challenge.ID, "t1", now, nil); err == nil {
			t.Error("SetChallengeValid() should fail when status is not processing")
		}

		// nonexistent challenge
		if err := storage.SetChallengeValid(ctx, "nonexistent", "t1", now, nil); err == nil {
			t.Error("SetChallengeValid() should fail for nonexistent challenge")
		}
	})

	t.Run("SetChallengeInvalid", func(t *testing.T) {
		t.Parallel()

		storage := newTestStorage(t)

		ctx := t.Context()
		challenge := &nanoca.Challenge{
			ID:     "invalid-challenge",
			Type:   "device-attest-01",
			Status: "pending",
			Token:  "test-token",
		}
		if err := storage.CreateChallenge(ctx, challenge); err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}
		if err := storage.ReserveChallengeValidation(ctx, challenge.ID, "t1", time.Minute); err != nil {
			t.Fatalf("ReserveChallengeValidation() error = %v", err)
		}

		now := time.Now()
		prob := nanoca.Unauthorized("device not authorized")

		if err := storage.SetChallengeInvalid(ctx, challenge.ID, "stale", now, prob); !errors.Is(err, nanoca.ErrReserved) {
			t.Errorf("SetChallengeInvalid(stale token) error = %v, want ErrReserved", err)
		}

		if err := storage.SetChallengeInvalid(ctx, challenge.ID, "t1", now, prob); err != nil {
			t.Fatalf("SetChallengeInvalid() error = %v", err)
		}

		retrieved, err := storage.GetChallenge(ctx, challenge.ID)
		if err != nil {
			t.Fatalf("GetChallenge() error = %v", err)
		}
		if retrieved.Status != "invalid" {
			t.Errorf("Status = %v, want invalid", retrieved.Status)
		}
		if retrieved.Validated == nil {
			t.Error("Validated should be set")
		}
		if retrieved.Error == nil {
			t.Error("Error should be set")
		}
		if retrieved.Reservation != nil {
			t.Error("Reservation should be cleared by the terminal write")
		}

		// calling on an invalid challenge should fail (expects processing)
		if err := storage.SetChallengeInvalid(ctx, challenge.ID, "t1", now, prob); err == nil {
			t.Error("SetChallengeInvalid() should fail when status is not processing")
		}

		// nonexistent challenge
		if err := storage.SetChallengeInvalid(ctx, "nonexistent", "t1", now, prob); err == nil {
			t.Error("SetChallengeInvalid() should fail for nonexistent challenge")
		}
	})
}

// storeCertificate persists a certificate the way the CA does: by reserving
// and completing a ready order.
func storeCertificate(t *testing.T, s *Storage, cert *nanoca.Certificate) {
	t.Helper()
	ctx := t.Context()

	if err := s.CreateOrder(ctx, &nanoca.Order{ID: cert.ID, Status: nanoca.OrderStatusReady}); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}
	if err := s.ReserveOrderFinalize(ctx, cert.ID, "token", time.Minute); err != nil {
		t.Fatalf("ReserveOrderFinalize() error = %v", err)
	}
	if err := s.CompleteOrder(ctx, &nanoca.Order{ID: cert.ID, Status: nanoca.OrderStatusValid}, cert, "token"); err != nil {
		t.Fatalf("CompleteOrder() error = %v", err)
	}
}

func TestStorage_CertificateOperations(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)

	ctx := t.Context()
	cert := &nanoca.Certificate{
		ID:           "order-1",
		SerialNumber: "test-cert-123",
		Raw:          []byte("dummy-cert-data"),
		Certificate:  &x509.Certificate{},
	}
	storeCertificate(t, storage, cert)

	_, err := storage.GetCertificate(ctx, cert.ID)
	if err == nil {
		t.Error("GetCertificate() should fail with dummy certificate data")
	}

	_, err = storage.GetCertificate(ctx, "nonexistent")
	if err == nil {
		t.Error("GetCertificate() should fail for nonexistent certificate")
	}
}

func TestStorage_CompleteOrder(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	ctx := t.Context()

	if err := storage.CreateOrder(ctx, &nanoca.Order{ID: "o1", Status: nanoca.OrderStatusPending}); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}
	// Deliberately not pre-set to valid: CompleteOrder owns the
	// processing-to-valid transition.
	order := &nanoca.Order{ID: "o1", Status: nanoca.OrderStatusProcessing}
	cert := &nanoca.Certificate{ID: "o1", SerialNumber: "1"}

	// Completion requires a reserved (processing) order.
	if err := storage.CompleteOrder(ctx, order, cert, "t1"); !errors.Is(err, nanoca.ErrStatusMismatch) {
		t.Errorf("CompleteOrder(pending) error = %v, want ErrStatusMismatch", err)
	}
	if err := storage.SetOrderStatus(ctx, "o1", nanoca.OrderStatusPending, nanoca.OrderStatusReady); err != nil {
		t.Fatalf("SetOrderStatus() error = %v", err)
	}
	if err := storage.CompleteOrder(ctx, order, cert, "t1"); !errors.Is(err, nanoca.ErrStatusMismatch) {
		t.Errorf("CompleteOrder(ready, unreserved) error = %v, want ErrStatusMismatch", err)
	}
	if _, err := storage.GetCertificate(ctx, "o1"); !errors.Is(err, nanoca.ErrNotFound) {
		t.Errorf("GetCertificate() after failed completion error = %v, want ErrNotFound", err)
	}

	if err := storage.ReserveOrderFinalize(ctx, "o1", "t1", time.Minute); err != nil {
		t.Fatalf("ReserveOrderFinalize() error = %v", err)
	}
	if err := storage.CompleteOrder(ctx, order, cert, "stale"); !errors.Is(err, nanoca.ErrReserved) {
		t.Errorf("CompleteOrder(stale token) error = %v, want ErrReserved", err)
	}
	if err := storage.CompleteOrder(ctx, order, cert, "t1"); err != nil {
		t.Fatalf("CompleteOrder() error = %v", err)
	}

	got, err := storage.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if got.Status != nanoca.OrderStatusValid {
		t.Errorf("order status = %q, want %q", got.Status, nanoca.OrderStatusValid)
	}
	if got.Reservation != nil {
		t.Error("Reservation should be cleared by completion")
	}
	if _, err := storage.GetCertificate(ctx, "o1"); err != nil {
		t.Errorf("GetCertificate() error = %v", err)
	}

	if err := storage.CompleteOrder(ctx, order, cert, "t1"); !errors.Is(err, nanoca.ErrStatusMismatch) {
		t.Errorf("CompleteOrder(valid) error = %v, want ErrStatusMismatch", err)
	}
}

func TestReserveOrderFinalize(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	ctx := t.Context()

	if err := storage.CreateOrder(ctx, &nanoca.Order{ID: "o1", Status: nanoca.OrderStatusPending}); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}
	if err := storage.ReserveOrderFinalize(ctx, "o1", "t1", time.Minute); !errors.Is(err, nanoca.ErrStatusMismatch) {
		t.Errorf("ReserveOrderFinalize(pending) error = %v, want ErrStatusMismatch", err)
	}

	if err := storage.SetOrderStatus(ctx, "o1", nanoca.OrderStatusPending, nanoca.OrderStatusReady); err != nil {
		t.Fatalf("SetOrderStatus() error = %v", err)
	}
	if err := storage.ReserveOrderFinalize(ctx, "o1", "t1", time.Minute); err != nil {
		t.Fatalf("ReserveOrderFinalize() error = %v", err)
	}

	order, err := storage.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if order.Status != nanoca.OrderStatusProcessing {
		t.Errorf("order status = %q, want %q", order.Status, nanoca.OrderStatusProcessing)
	}
	if order.Reservation == nil || order.Reservation.Token != "t1" {
		t.Errorf("Reservation = %+v, want token t1", order.Reservation)
	}

	if err := storage.ReserveOrderFinalize(ctx, "o1", "t2", time.Minute); !errors.Is(err, nanoca.ErrReserved) {
		t.Errorf("ReserveOrderFinalize(reserved) error = %v, want ErrReserved", err)
	}

	// A negative lease makes the reservation already expired: a retry
	// reclaims a finalize abandoned by a crashed holder.
	if err := storage.ReserveOrderFinalize(ctx, "o1", "t2", -time.Second); err != nil {
		t.Errorf("ReserveOrderFinalize(expired) error = %v, want success", err)
	}
	order, err = storage.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if order.Reservation == nil || order.Reservation.Token != "t2" {
		t.Errorf("Reservation after reclaim = %+v, want token t2", order.Reservation)
	}
}

func TestReleaseOrderFinalize(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	ctx := t.Context()

	if err := storage.CreateOrder(ctx, &nanoca.Order{ID: "o1", Status: nanoca.OrderStatusReady}); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}
	if err := storage.ReleaseOrderFinalize(ctx, "o1", "t1", nanoca.OrderStatusReady); !errors.Is(err, nanoca.ErrStatusMismatch) {
		t.Errorf("ReleaseOrderFinalize(ready) error = %v, want ErrStatusMismatch", err)
	}

	if err := storage.ReserveOrderFinalize(ctx, "o1", "t1", time.Minute); err != nil {
		t.Fatalf("ReserveOrderFinalize() error = %v", err)
	}
	if err := storage.ReleaseOrderFinalize(ctx, "o1", "stale", nanoca.OrderStatusReady); !errors.Is(err, nanoca.ErrReserved) {
		t.Errorf("ReleaseOrderFinalize(stale token) error = %v, want ErrReserved", err)
	}
	if err := storage.ReleaseOrderFinalize(ctx, "o1", "t1", nanoca.OrderStatusReady); err != nil {
		t.Fatalf("ReleaseOrderFinalize() error = %v", err)
	}

	order, err := storage.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if order.Status != nanoca.OrderStatusReady {
		t.Errorf("order status = %q, want %q", order.Status, nanoca.OrderStatusReady)
	}
	if order.Reservation != nil {
		t.Error("Reservation should be cleared by release")
	}
}

func TestReleaseChallengeValidation(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	ctx := t.Context()

	if err := storage.CreateChallenge(ctx, &nanoca.Challenge{ID: "c1", Status: nanoca.ChallengeStatusPending}); err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}
	if err := storage.ReleaseChallengeValidation(ctx, "c1", "t1"); !errors.Is(err, nanoca.ErrStatusMismatch) {
		t.Errorf("ReleaseChallengeValidation(pending) error = %v, want ErrStatusMismatch", err)
	}

	if err := storage.ReserveChallengeValidation(ctx, "c1", "t1", time.Minute); err != nil {
		t.Fatalf("ReserveChallengeValidation() error = %v", err)
	}
	if err := storage.ReleaseChallengeValidation(ctx, "c1", "stale"); !errors.Is(err, nanoca.ErrReserved) {
		t.Errorf("ReleaseChallengeValidation(stale token) error = %v, want ErrReserved", err)
	}
	if err := storage.ReleaseChallengeValidation(ctx, "c1", "t1"); err != nil {
		t.Fatalf("ReleaseChallengeValidation() error = %v", err)
	}

	challenge, err := storage.GetChallenge(ctx, "c1")
	if err != nil {
		t.Fatalf("GetChallenge() error = %v", err)
	}
	if challenge.Status != nanoca.ChallengeStatusPending {
		t.Errorf("challenge status = %q, want %q", challenge.Status, nanoca.ChallengeStatusPending)
	}
	if challenge.Reservation != nil {
		t.Error("Reservation should be cleared by release")
	}
}

func TestKeyGenerationFunctions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fn   func(string) []byte
		id   string
		want string
	}{
		{"nonceKey", nonceKey, "test", "nonce:test"},
		{"accountKey", accountKey, "test", "account:test"},
		{"accountKeyLookupKey", accountKeyLookupKey, "test", "account_key:test"},
		{"orderKey", orderKey, "test", "order:test"},
		{"authzKey", authzKey, "test", "authz:test"},
		{"challengeKey", challengeKey, "test", "challenge:test"},
		{"certificateKey", certificateKey, "test", "cert:test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := string(tt.fn(tt.id))
			if result != tt.want {
				t.Errorf("%s() = %v, want %v", tt.name, result, tt.want)
			}
		})
	}
}
