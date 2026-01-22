package badger

import (
	"crypto/x509"
	"errors"
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

func TestStorage_NonceOperations(t *testing.T) {
	t.Parallel()

	storage, err := New(Options{InMemory: true})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	ctx := t.Context()
	nonce := &nanoca.Nonce{
		Value:     "test-nonce-123",
		CreatedAt: time.Now(),
	}

	err = storage.CreateNonce(ctx, nonce)
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
	if !errors.Is(err, nanoca.ErrNonceNotFound) {
		t.Errorf("ConsumeNonce() error = %v, want ErrNonceNotFound", err)
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

func TestStorage_AccountOperations(t *testing.T) {
	t.Parallel()

	storage, err := New(Options{InMemory: true})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	ctx := t.Context()
	account := &nanoca.Account{
		ID:       "test-account-123",
		Contact:  []string{"mailto:test@example.com"},
		Status:   "valid",
		KeyBytes: []byte("key-thumbprint-hash"),
	}

	err = storage.CreateAccount(ctx, account)
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

	retrieved, err = storage.GetAccountByKey(ctx, string(account.KeyBytes))
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

	storage, err := New(Options{InMemory: true})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	ctx := t.Context()
	expires := time.Now().Add(24 * time.Hour)
	order := &nanoca.Order{
		ID:          "test-order-123",
		AccountID:   "account-123",
		Status:      "pending",
		Expires:     &expires,
		Identifiers: []nanoca.Identifier{{Type: "permanent-identifier", Value: "device-123"}},
	}

	err = storage.CreateOrder(ctx, order)
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

	order.Status = "ready"
	err = storage.UpdateOrder(ctx, order)
	if err != nil {
		t.Errorf("UpdateOrder() error = %v", err)
	}

	retrieved, err = storage.GetOrder(ctx, order.ID)
	if err != nil {
		t.Errorf("GetOrder() after update error = %v", err)
	}
	if retrieved.Status != "ready" {
		t.Errorf("UpdateOrder() status = %v, want ready", retrieved.Status)
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

	nonExistent := &nanoca.Order{ID: "nonexistent"}
	err = storage.UpdateOrder(ctx, nonExistent)
	if err == nil {
		t.Error("UpdateOrder() should fail for nonexistent order")
	}
}

func TestStorage_AuthorizationOperations(t *testing.T) {
	t.Parallel()

	storage, err := New(Options{InMemory: true})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	ctx := t.Context()
	authzExpires := time.Now().Add(24 * time.Hour)
	authz := &nanoca.Authorization{
		ID:         "test-authz-123",
		Status:     "pending",
		Expires:    &authzExpires,
		Identifier: nanoca.Identifier{Type: "permanent-identifier", Value: "device-123"},
	}

	err = storage.CreateAuthorization(ctx, authz)
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
	err = storage.UpdateAuthorization(ctx, authz)
	if err != nil {
		t.Errorf("UpdateAuthorization() error = %v", err)
	}

	retrieved, err = storage.GetAuthorization(ctx, authz.ID)
	if err != nil {
		t.Errorf("GetAuthorization() after update error = %v", err)
	}
	if retrieved.Status != "valid" {
		t.Errorf("UpdateAuthorization() status = %v, want valid", retrieved.Status)
	}

	_, err = storage.GetAuthorization(ctx, "nonexistent")
	if err == nil {
		t.Error("GetAuthorization() should fail for nonexistent authorization")
	}

	nonExistent := &nanoca.Authorization{ID: "nonexistent"}
	err = storage.UpdateAuthorization(ctx, nonExistent)
	if err == nil {
		t.Error("UpdateAuthorization() should fail for nonexistent authorization")
	}
}

func TestStorage_ChallengeOperations(t *testing.T) {
	t.Parallel()

	t.Run("CreateAndGet", func(t *testing.T) {
		t.Parallel()

		storage, err := New(Options{InMemory: true})
		if err != nil {
			t.Fatalf("Failed to create storage: %v", err)
		}
		defer storage.Close()

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

	t.Run("SetChallengeProcessing", func(t *testing.T) {
		t.Parallel()

		storage, err := New(Options{InMemory: true})
		if err != nil {
			t.Fatalf("Failed to create storage: %v", err)
		}
		defer storage.Close()

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

		if err := storage.SetChallengeProcessing(ctx, challenge.ID); err != nil {
			t.Fatalf("SetChallengeProcessing() error = %v", err)
		}

		retrieved, err := storage.GetChallenge(ctx, challenge.ID)
		if err != nil {
			t.Fatalf("GetChallenge() error = %v", err)
		}
		if retrieved.Status != "processing" {
			t.Errorf("Status = %v, want processing", retrieved.Status)
		}

		// calling again should fail (status is now processing, not pending)
		if err := storage.SetChallengeProcessing(ctx, challenge.ID); err == nil {
			t.Error("SetChallengeProcessing() should fail when status is not pending")
		}

		// nonexistent challenge
		if err := storage.SetChallengeProcessing(ctx, "nonexistent"); err == nil {
			t.Error("SetChallengeProcessing() should fail for nonexistent challenge")
		}
	})

	t.Run("SetChallengeValid", func(t *testing.T) {
		t.Parallel()

		storage, err := New(Options{InMemory: true})
		if err != nil {
			t.Fatalf("Failed to create storage: %v", err)
		}
		defer storage.Close()

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
		if err := storage.SetChallengeProcessing(ctx, challenge.ID); err != nil {
			t.Fatalf("SetChallengeProcessing() error = %v", err)
		}

		now := time.Now()
		attestation := map[string]any{"fmt": "none", "key": "value"}
		if err := storage.SetChallengeValid(ctx, challenge.ID, now, attestation); err != nil {
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

		// calling on a valid challenge should fail (expects processing)
		if err := storage.SetChallengeValid(ctx, challenge.ID, now, nil); err == nil {
			t.Error("SetChallengeValid() should fail when status is not processing")
		}

		// nonexistent challenge
		if err := storage.SetChallengeValid(ctx, "nonexistent", now, nil); err == nil {
			t.Error("SetChallengeValid() should fail for nonexistent challenge")
		}
	})

	t.Run("SetChallengeInvalid", func(t *testing.T) {
		t.Parallel()

		storage, err := New(Options{InMemory: true})
		if err != nil {
			t.Fatalf("Failed to create storage: %v", err)
		}
		defer storage.Close()

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
		if err := storage.SetChallengeProcessing(ctx, challenge.ID); err != nil {
			t.Fatalf("SetChallengeProcessing() error = %v", err)
		}

		now := time.Now()
		prob := nanoca.Unauthorized("device not authorized")
		if err := storage.SetChallengeInvalid(ctx, challenge.ID, now, prob); err != nil {
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

		// calling on an invalid challenge should fail (expects processing)
		if err := storage.SetChallengeInvalid(ctx, challenge.ID, now, prob); err == nil {
			t.Error("SetChallengeInvalid() should fail when status is not processing")
		}

		// nonexistent challenge
		if err := storage.SetChallengeInvalid(ctx, "nonexistent", now, prob); err == nil {
			t.Error("SetChallengeInvalid() should fail for nonexistent challenge")
		}
	})
}

func TestStorage_CertificateOperations(t *testing.T) {
	t.Parallel()

	storage, err := New(Options{InMemory: true})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	ctx := t.Context()
	cert := &nanoca.Certificate{
		SerialNumber: "test-cert-123",
		Raw:          []byte("dummy-cert-data"),
		Certificate:  &x509.Certificate{},
	}

	err = storage.CreateCertificate(ctx, cert)
	if err != nil {
		t.Errorf("CreateCertificate() error = %v", err)
	}

	_, err = storage.GetCertificate(ctx, cert.SerialNumber)
	if err == nil {
		t.Error("GetCertificate() should fail with dummy certificate data")
	}

	_, err = storage.GetCertificate(ctx, "nonexistent")
	if err == nil {
		t.Error("GetCertificate() should fail for nonexistent certificate")
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
