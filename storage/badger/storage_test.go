package badger

import (
	"errors"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/storage/storagetest"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    func(t *testing.T) Options
		wantErr bool
	}{
		{
			name: "in-memory storage",
			opts: func(*testing.T) Options { return Options{InMemory: true} },
		},
		{
			name:    "no path for persistent storage",
			opts:    func(*testing.T) Options { return Options{} },
			wantErr: true,
		},
		{
			name: "with path for persistent storage",
			opts: func(t *testing.T) Options { return Options{Path: t.TempDir()} },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			storage, err := New(tt.opts(t))
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

func TestConformanceInMemory(t *testing.T) {
	t.Parallel()

	storagetest.RunConformanceTests(t, func(t *testing.T) nanoca.Storage {
		return newTestStorage(t)
	})
}

func TestConformanceOnDisk(t *testing.T) {
	t.Parallel()

	storagetest.RunConformanceTests(t, func(t *testing.T) nanoca.Storage {
		storage, err := New(Options{Path: t.TempDir()})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		t.Cleanup(func() { storage.Close() })
		return storage
	})
}

// Revisions are an explicit counter in the stored envelope, so they must
// survive closing and reopening the database.
func TestRevisionSurvivesReopen(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := t.Context()

	storage, err := New(Options{Path: dir})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := storage.CreateOrder(ctx, &nanoca.Order{ID: "o1", Status: nanoca.OrderStatusPending}, nil, nil); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}
	order, rev, err := storage.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if err := storage.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := New(Options{Path: dir})
	if err != nil {
		t.Fatalf("New(reopen) error = %v", err)
	}
	t.Cleanup(func() { reopened.Close() })

	got, gotRev, err := reopened.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder(reopened) error = %v", err)
	}
	if gotRev != rev {
		t.Errorf("revision after reopen = %s, want %s", gotRev, rev)
	}
	if got.Status != order.Status {
		t.Errorf("order status after reopen = %s, want %s", got.Status, order.Status)
	}

	// The revision still gates writes after the reopen.
	got.Status = nanoca.OrderStatusReady
	if err := reopened.PutOrder(ctx, got, gotRev); err != nil {
		t.Fatalf("PutOrder(reopened) error = %v", err)
	}
	if err := reopened.PutOrder(ctx, got, gotRev); err == nil {
		t.Error("PutOrder(stale revision after reopen) error = nil, want ErrConflict")
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

// The ttl hint lets badger evict a nonce that is never taken. ExpiresAt is
// stored at second granularity, so a tiny ttl can straddle a second
// boundary; poll briefly instead of asserting the first read.
func TestCreateNonceTTLEvicts(t *testing.T) {
	t.Parallel()

	s := newTestStorage(t)
	nonce := &nanoca.Nonce{Value: "n1", CreatedAt: time.Now()}
	if err := s.CreateNonce(t.Context(), nonce, time.Nanosecond); err != nil {
		t.Fatalf("CreateNonce() error = %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := s.TakeNonce(t.Context(), "n1")
		if errors.Is(err, nanoca.ErrNotFound) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("TakeNonce(evicted) error = %v, want ErrNotFound", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
