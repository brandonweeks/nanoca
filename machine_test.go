package nanoca

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func newTestMachine(t *testing.T) (*storageMachine, *MemoryStorage) {
	t.Helper()
	backend := NewMemoryStorage()
	return newStorageMachine(backend), backend
}

func createOrderRecord(t *testing.T, m *storageMachine, order *Order) {
	t.Helper()
	if err := m.CreateOrder(t.Context(), order, nil, nil); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}
}

func createChallengeRecord(t *testing.T, m *storageMachine, challenge *Challenge) {
	t.Helper()
	order := &Order{ID: "order-for-" + challenge.ID, Status: OrderStatusPending}
	if err := m.CreateOrder(t.Context(), order, nil, []*Challenge{challenge}); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}
}

func TestMachineNotFound(t *testing.T) {
	t.Parallel()

	m, _ := newTestMachine(t)
	ctx := t.Context()

	for name, op := range map[string]func() error{
		"SetOrderStatus": func() error {
			return m.SetOrderStatus(ctx, "ghost", OrderStatusPending, OrderStatusReady)
		},
		"ReserveOrderFinalize": func() error {
			return m.ReserveOrderFinalize(ctx, "ghost", "t", time.Minute)
		},
		"ReleaseOrderFinalize": func() error {
			return m.ReleaseOrderFinalize(ctx, "ghost", "t", OrderStatusReady)
		},
		"SettleAuthorization": func() error {
			return m.SettleAuthorization(ctx, &Authorization{ID: "ghost", Status: AuthzStatusValid})
		},
		"ReserveChallengeValidation": func() error {
			return m.ReserveChallengeValidation(ctx, "ghost", "t", time.Minute)
		},
		"SettleChallenge": func() error {
			return m.SettleChallenge(ctx, &Challenge{ID: "ghost"}, "t")
		},
		"CompleteOrder": func() error {
			return m.CompleteOrder(ctx, &Order{ID: "ghost"}, &Certificate{ID: "ghost-cert"}, "t")
		},
		"ConsumeNonce": func() error {
			_, err := m.ConsumeNonce(ctx, "ghost", time.Hour)
			return err
		},
	} {
		if err := op(); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s(missing) error = %v, want ErrNotFound", name, err)
		}
	}
}

func TestMachineConsumeNonce(t *testing.T) {
	t.Parallel()

	m, _ := newTestMachine(t)
	ctx := t.Context()

	if err := m.CreateNonce(ctx, &Nonce{Value: "n1", CreatedAt: time.Now()}, time.Hour); err != nil {
		t.Fatalf("CreateNonce() error = %v", err)
	}
	if _, err := m.ConsumeNonce(ctx, "n1", time.Hour); err != nil {
		t.Errorf("ConsumeNonce() error = %v", err)
	}
	if _, err := m.ConsumeNonce(ctx, "n1", time.Hour); !errors.Is(err, ErrNotFound) {
		t.Errorf("ConsumeNonce(consumed) error = %v, want ErrNotFound", err)
	}

	// An expired nonce reports expiry and is still consumed, so it cannot
	// linger forever.
	if err := m.CreateNonce(ctx, &Nonce{Value: "n2", CreatedAt: time.Now().Add(-2 * time.Hour)}, time.Hour); err != nil {
		t.Fatalf("CreateNonce() error = %v", err)
	}
	if _, err := m.ConsumeNonce(ctx, "n2", time.Hour); !errors.Is(err, ErrNonceExpired) {
		t.Errorf("ConsumeNonce(expired) error = %v, want ErrNonceExpired", err)
	}
	if _, err := m.ConsumeNonce(ctx, "n2", time.Hour); !errors.Is(err, ErrNotFound) {
		t.Errorf("ConsumeNonce(expired, again) error = %v, want ErrNotFound", err)
	}
}

func TestMachineCreateAccountExists(t *testing.T) {
	t.Parallel()

	m, _ := newTestMachine(t)
	ctx := t.Context()

	if err := m.CreateAccount(ctx, &Account{ID: "a1", KeyThumbprint: "thumb"}); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	err := m.CreateAccount(ctx, &Account{ID: "a2", KeyThumbprint: "thumb"})
	if !errors.Is(err, ErrAccountExists) {
		t.Errorf("CreateAccount(duplicate key) error = %v, want ErrAccountExists", err)
	}
}

func TestMachineSetOrderStatus(t *testing.T) {
	t.Parallel()

	m, _ := newTestMachine(t)
	ctx := t.Context()
	createOrderRecord(t, m, &Order{ID: "o1", Status: OrderStatusPending})

	if err := m.SetOrderStatus(ctx, "o1", OrderStatusPending, OrderStatusReady); err != nil {
		t.Fatalf("SetOrderStatus() error = %v", err)
	}
	order, err := m.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if order.Status != OrderStatusReady {
		t.Errorf("order status = %q, want %q", order.Status, OrderStatusReady)
	}

	// A stale caller cannot overwrite a transition that already happened.
	if err := m.SetOrderStatus(ctx, "o1", OrderStatusPending, OrderStatusInvalid); !errors.Is(err, ErrStatusMismatch) {
		t.Errorf("SetOrderStatus(stale) error = %v, want ErrStatusMismatch", err)
	}
}

func TestMachineReserveOrderFinalize(t *testing.T) {
	t.Parallel()

	m, _ := newTestMachine(t)
	ctx := t.Context()
	createOrderRecord(t, m, &Order{ID: "o1", Status: OrderStatusPending})

	if err := m.ReserveOrderFinalize(ctx, "o1", "t1", time.Minute); !errors.Is(err, ErrStatusMismatch) {
		t.Errorf("ReserveOrderFinalize(pending) error = %v, want ErrStatusMismatch", err)
	}

	if err := m.SetOrderStatus(ctx, "o1", OrderStatusPending, OrderStatusReady); err != nil {
		t.Fatalf("SetOrderStatus() error = %v", err)
	}
	if err := m.ReserveOrderFinalize(ctx, "o1", "t1", time.Minute); err != nil {
		t.Fatalf("ReserveOrderFinalize() error = %v", err)
	}
	order, err := m.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if order.Status != OrderStatusProcessing || order.Reservation == nil || order.Reservation.Token != "t1" {
		t.Errorf("reserved order = %+v, want processing with token t1", order)
	}

	// A live reservation refuses a second holder.
	if err := m.ReserveOrderFinalize(ctx, "o1", "t2", time.Minute); !errors.Is(err, ErrReserved) {
		t.Errorf("ReserveOrderFinalize(reserved) error = %v, want ErrReserved", err)
	}

	// A negative lease makes the reservation already lapsed: a retry
	// reclaims it with a fresh token.
	if err := m.ReserveOrderFinalize(ctx, "o1", "t2", -time.Second); err != nil {
		t.Errorf("ReserveOrderFinalize(lapsed) error = %v, want success", err)
	}
	order, err = m.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if order.Reservation == nil || order.Reservation.Token != "t2" {
		t.Errorf("reservation after reclaim = %+v, want token t2", order.Reservation)
	}
}

func TestMachineReleaseOrderFinalize(t *testing.T) {
	t.Parallel()

	m, _ := newTestMachine(t)
	ctx := t.Context()
	createOrderRecord(t, m, &Order{ID: "o1", Status: OrderStatusReady})

	if err := m.ReleaseOrderFinalize(ctx, "o1", "t1", OrderStatusReady); !errors.Is(err, ErrStatusMismatch) {
		t.Errorf("ReleaseOrderFinalize(unreserved) error = %v, want ErrStatusMismatch", err)
	}

	if err := m.ReserveOrderFinalize(ctx, "o1", "t1", time.Minute); err != nil {
		t.Fatalf("ReserveOrderFinalize() error = %v", err)
	}
	if err := m.ReleaseOrderFinalize(ctx, "o1", "stale", OrderStatusReady); !errors.Is(err, ErrReserved) {
		t.Errorf("ReleaseOrderFinalize(stale token) error = %v, want ErrReserved", err)
	}
	if err := m.ReleaseOrderFinalize(ctx, "o1", "t1", OrderStatusReady); err != nil {
		t.Fatalf("ReleaseOrderFinalize() error = %v", err)
	}

	order, err := m.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if order.Status != OrderStatusReady {
		t.Errorf("order status = %q, want %q", order.Status, OrderStatusReady)
	}
	if order.Reservation != nil {
		t.Error("Reservation should be cleared by release")
	}
}

func TestMachineCompleteOrder(t *testing.T) {
	t.Parallel()

	m, backend := newTestMachine(t)
	ctx := t.Context()
	createOrderRecord(t, m, &Order{ID: "o1", Status: OrderStatusPending})

	// Deliberately not pre-set to valid: CompleteOrder owns the
	// processing-to-valid transition.
	order := &Order{ID: "o1", Status: OrderStatusProcessing}

	// Completion requires a reserved (processing) order. The certificate
	// write is unconditional, so a failed completion leaves it stored but
	// referenced by no order.
	if err := m.CompleteOrder(ctx, order, &Certificate{ID: "attempt-1"}, "t1"); !errors.Is(err, ErrStatusMismatch) {
		t.Errorf("CompleteOrder(pending) error = %v, want ErrStatusMismatch", err)
	}
	if _, err := backend.GetCertificate(ctx, "attempt-1"); err != nil {
		t.Errorf("GetCertificate(orphan) error = %v, want stored", err)
	}
	stored, err := m.GetOrder(ctx, "o1")
	if err != nil || stored.Status != OrderStatusPending || stored.Certificate != "" {
		t.Errorf("order after failed completion = %+v, %v, want untouched pending", stored, err)
	}

	if err := m.SetOrderStatus(ctx, "o1", OrderStatusPending, OrderStatusReady); err != nil {
		t.Fatalf("SetOrderStatus() error = %v", err)
	}
	if err := m.ReserveOrderFinalize(ctx, "o1", "t1", time.Minute); err != nil {
		t.Fatalf("ReserveOrderFinalize() error = %v", err)
	}
	if err := m.CompleteOrder(ctx, order, &Certificate{ID: "attempt-2"}, "stale"); !errors.Is(err, ErrReserved) {
		t.Errorf("CompleteOrder(stale token) error = %v, want ErrReserved", err)
	}
	stored, err = m.GetOrder(ctx, "o1")
	if err != nil || stored.Status != OrderStatusProcessing || stored.Reservation == nil || stored.Reservation.Token != "t1" {
		t.Errorf("order after lost completion = %+v, %v, want processing held by t1", stored, err)
	}

	if err := m.CompleteOrder(ctx, order, &Certificate{ID: "attempt-3", SerialNumber: "1"}, "t1"); err != nil {
		t.Fatalf("CompleteOrder() error = %v", err)
	}
	stored, err = m.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if stored.Status != OrderStatusValid {
		t.Errorf("order status = %q, want %q", stored.Status, OrderStatusValid)
	}
	if stored.Reservation != nil {
		t.Error("Reservation should be cleared by completion")
	}
	if _, err := m.GetCertificate(ctx, "attempt-3"); err != nil {
		t.Errorf("GetCertificate() error = %v", err)
	}

	if err := m.CompleteOrder(ctx, order, &Certificate{ID: "attempt-4"}, "t1"); !errors.Is(err, ErrStatusMismatch) {
		t.Errorf("CompleteOrder(valid) error = %v, want ErrStatusMismatch", err)
	}
}

func TestMachineChallengeLifecycle(t *testing.T) {
	t.Parallel()

	m, _ := newTestMachine(t)
	ctx := t.Context()
	challenge := &Challenge{ID: "c1", Type: ChallengeTypeDeviceAttest01, Status: ChallengeStatusPending, Token: "tok"}
	createChallengeRecord(t, m, challenge)

	if err := m.ReserveChallengeValidation(ctx, "c1", "t1", time.Minute); err != nil {
		t.Fatalf("ReserveChallengeValidation() error = %v", err)
	}
	if err := m.ReserveChallengeValidation(ctx, "c1", "t2", time.Minute); !errors.Is(err, ErrReserved) {
		t.Errorf("ReserveChallengeValidation(reserved) error = %v, want ErrReserved", err)
	}

	now := time.Now()
	settled := *challenge
	settled.settleValid(now, []byte("attestation-object"))

	if err := m.SettleChallenge(ctx, &settled, "stale"); !errors.Is(err, ErrReserved) {
		t.Errorf("SettleChallenge(stale token) error = %v, want ErrReserved", err)
	}
	if err := m.SettleChallenge(ctx, &settled, "t1"); err != nil {
		t.Fatalf("SettleChallenge() error = %v", err)
	}

	got, err := m.GetChallenge(ctx, "c1")
	if err != nil {
		t.Fatalf("GetChallenge() error = %v", err)
	}
	if got.Status != ChallengeStatusValid || got.Validated == nil || got.Attestation == nil || got.Error != nil {
		t.Errorf("settled challenge = %+v, want valid with attestation", got)
	}
	if got.Reservation != nil {
		t.Error("Reservation should be cleared by the terminal write")
	}

	// Valid is terminal: neither settle nor reserve may touch it again.
	if err := m.SettleChallenge(ctx, &settled, "t1"); !errors.Is(err, ErrStatusMismatch) {
		t.Errorf("SettleChallenge(valid) error = %v, want ErrStatusMismatch", err)
	}
	if err := m.ReserveChallengeValidation(ctx, "c1", "t3", time.Minute); !errors.Is(err, ErrStatusMismatch) {
		t.Errorf("ReserveChallengeValidation(valid) error = %v, want ErrStatusMismatch", err)
	}
}

func TestMachineChallengeReclaim(t *testing.T) {
	t.Parallel()

	m, _ := newTestMachine(t)
	ctx := t.Context()
	createChallengeRecord(t, m, &Challenge{ID: "c1", Status: ChallengeStatusPending})

	if err := m.ReserveChallengeValidation(ctx, "c1", "t1", time.Minute); err != nil {
		t.Fatalf("ReserveChallengeValidation() error = %v", err)
	}
	// A negative lease makes the reservation already lapsed: a retried
	// POST reclaims a validation interrupted before a terminal status.
	if err := m.ReserveChallengeValidation(ctx, "c1", "t2", -time.Second); err != nil {
		t.Errorf("ReserveChallengeValidation(lapsed) error = %v, want success", err)
	}
	got, err := m.GetChallenge(ctx, "c1")
	if err != nil {
		t.Fatalf("GetChallenge() error = %v", err)
	}
	if got.Reservation == nil || got.Reservation.Token != "t2" {
		t.Errorf("reservation after reclaim = %+v, want token t2", got.Reservation)
	}
}

func TestMachineSettleChallengeToPending(t *testing.T) {
	t.Parallel()

	m, _ := newTestMachine(t)
	ctx := t.Context()
	challenge := &Challenge{ID: "c1", Status: ChallengeStatusPending}
	createChallengeRecord(t, m, challenge)

	if err := m.SettleChallenge(ctx, challenge, "t1"); !errors.Is(err, ErrStatusMismatch) {
		t.Errorf("SettleChallenge(pending) error = %v, want ErrStatusMismatch", err)
	}

	if err := m.ReserveChallengeValidation(ctx, "c1", "t1", time.Minute); err != nil {
		t.Fatalf("ReserveChallengeValidation() error = %v", err)
	}

	// Settling back to pending surrenders the reservation so a retry can
	// validate again after a transient failure.
	surrendered := *challenge
	surrendered.settlePending()
	if err := m.SettleChallenge(ctx, &surrendered, "t1"); err != nil {
		t.Fatalf("SettleChallenge(pending) error = %v", err)
	}
	got, err := m.GetChallenge(ctx, "c1")
	if err != nil {
		t.Fatalf("GetChallenge() error = %v", err)
	}
	if got.Status != ChallengeStatusPending || got.Reservation != nil {
		t.Errorf("surrendered challenge = %+v, want pending and unreserved", got)
	}
	if err := m.ReserveChallengeValidation(ctx, "c1", "t2", time.Minute); err != nil {
		t.Errorf("ReserveChallengeValidation(after surrender) error = %v", err)
	}
}

func TestMachineSettleAuthorization(t *testing.T) {
	t.Parallel()

	m, _ := newTestMachine(t)
	ctx := t.Context()

	order := &Order{ID: "o1", Status: OrderStatusPending}
	authz := &Authorization{ID: "z1", OrderID: "o1", Status: AuthzStatusPending, ChallengeIDs: []string{"c1"}}
	challenge := &Challenge{ID: "c1", AuthzID: "z1", Status: ChallengeStatusValid}
	if err := m.CreateOrder(ctx, order, []*Authorization{authz}, []*Challenge{challenge}); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}

	settled := *authz
	settled.Status = AuthzStatusValid
	if err := m.SettleAuthorization(ctx, &settled); err != nil {
		t.Fatalf("SettleAuthorization() error = %v", err)
	}

	got, err := m.GetAuthorization(ctx, "z1")
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}
	if got.Status != AuthzStatusValid {
		t.Errorf("authorization status = %q, want %q", got.Status, AuthzStatusValid)
	}
	if len(got.Challenges) != 1 || got.Challenges[0].ID != "c1" {
		t.Errorf("composed challenges = %+v, want challenge c1", got.Challenges)
	}

	// The guard keeps a recompute from stale reads from overwriting a
	// settled authorization.
	settled.Status = AuthzStatusInvalid
	if err := m.SettleAuthorization(ctx, &settled); !errors.Is(err, ErrStatusMismatch) {
		t.Errorf("SettleAuthorization(settled) error = %v, want ErrStatusMismatch", err)
	}
}

// The composed challenge copies never reach the backend: the stored
// authorization names its challenges by ID only.
func TestMachineCreateOrderStripsComposedChallenges(t *testing.T) {
	t.Parallel()

	m, backend := newTestMachine(t)
	ctx := t.Context()

	authz := &Authorization{
		ID:           "z1",
		Status:       AuthzStatusPending,
		ChallengeIDs: []string{"c1"},
		Challenges:   []Challenge{{ID: "c1", Attestation: []byte("blob")}},
	}
	challenge := &Challenge{ID: "c1", AuthzID: "z1", Status: ChallengeStatusPending}
	if err := m.CreateOrder(ctx, &Order{ID: "o1"}, []*Authorization{authz}, []*Challenge{challenge}); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}

	stored, _, err := backend.GetAuthorization(ctx, "z1")
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}
	if len(stored.Challenges) != 0 {
		t.Errorf("stored authorization embeds %d challenge copies, want none", len(stored.Challenges))
	}
	if len(stored.ChallengeIDs) != 1 || stored.ChallengeIDs[0] != "c1" {
		t.Errorf("stored challenge IDs = %v, want [c1]", stored.ChallengeIDs)
	}
}

func TestMachineGetCertificateBadRaw(t *testing.T) {
	t.Parallel()

	m, backend := newTestMachine(t)
	ctx := t.Context()

	if err := backend.CreateCertificate(ctx, &Certificate{ID: "cert1", Raw: []byte("not-a-cert")}); err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	if _, err := m.GetCertificate(ctx, "cert1"); err == nil {
		t.Error("GetCertificate(bad raw) error = nil, want parse failure")
	}
}

// conflictingStorage rejects the first n conditional order writes with
// ErrConflict without changing the record, exercising the retry loop.
type conflictingStorage struct {
	Storage
	mu        sync.Mutex
	remaining int
	conflicts int
}

func (s *conflictingStorage) PutOrder(ctx context.Context, order *Order, rev Revision) error {
	s.mu.Lock()
	inject := s.remaining > 0
	if inject {
		s.remaining--
		s.conflicts++
	}
	s.mu.Unlock()
	if inject {
		return fmt.Errorf("injected: %w", ErrConflict)
	}
	return s.Storage.PutOrder(ctx, order, rev)
}

// A conflicted write retries from a fresh read until it lands; ErrConflict
// never escapes the machine.
func TestMachineRetriesOnConflict(t *testing.T) {
	t.Parallel()

	backend := &conflictingStorage{Storage: NewMemoryStorage(), remaining: 2}
	m := newStorageMachine(backend)
	ctx := t.Context()

	if err := m.CreateOrder(ctx, &Order{ID: "o1", Status: OrderStatusPending}, nil, nil); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}
	if err := m.SetOrderStatus(ctx, "o1", OrderStatusPending, OrderStatusReady); err != nil {
		t.Fatalf("SetOrderStatus() error = %v", err)
	}
	if backend.conflicts != 2 {
		t.Errorf("injected conflicts = %d, want 2", backend.conflicts)
	}
	order, err := m.GetOrder(ctx, "o1")
	if err != nil || order.Status != OrderStatusReady {
		t.Errorf("order after retries = %+v, %v, want ready", order, err)
	}
}

// A canceled context ends the retry loop instead of spinning.
func TestMachineRetryStopsOnCanceledContext(t *testing.T) {
	t.Parallel()

	backend := &conflictingStorage{Storage: NewMemoryStorage(), remaining: 1 << 30}
	m := newStorageMachine(backend)

	if err := m.CreateOrder(t.Context(), &Order{ID: "o1", Status: OrderStatusPending}, nil, nil); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := m.SetOrderStatus(ctx, "o1", OrderStatusPending, OrderStatusReady); !errors.Is(err, context.Canceled) {
		t.Errorf("SetOrderStatus(canceled) error = %v, want context.Canceled", err)
	}
}

// reserveRacingStorage lets a rival reserve the order between the
// machine's read and its write, so the machine's put conflicts and the
// retry must reclassify against the rival's reservation.
type reserveRacingStorage struct {
	Storage
	mu    sync.Mutex
	raced bool
}

func (s *reserveRacingStorage) PutOrder(ctx context.Context, order *Order, rev Revision) error {
	s.mu.Lock()
	race := !s.raced
	s.raced = true
	s.mu.Unlock()
	if race {
		stored, storedRev, err := s.GetOrder(ctx, order.ID)
		if err != nil {
			return err
		}
		stored.Status = OrderStatusProcessing
		stored.Reservation = &Reservation{Token: "rival", ReservedAt: time.Now()}
		if err := s.Storage.PutOrder(ctx, stored, storedRev); err != nil {
			return err
		}
	}
	return s.Storage.PutOrder(ctx, order, rev)
}

// Losing the conditional write to a rival reserver must classify as
// ErrReserved from the fresh read, not surface a conflict or succeed.
func TestMachineReclassifiesLostReserve(t *testing.T) {
	t.Parallel()

	backend := &reserveRacingStorage{Storage: NewMemoryStorage()}
	m := newStorageMachine(backend)
	ctx := t.Context()

	if err := m.CreateOrder(ctx, &Order{ID: "o1", Status: OrderStatusReady}, nil, nil); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}
	if err := m.ReserveOrderFinalize(ctx, "o1", "mine", time.Minute); !errors.Is(err, ErrReserved) {
		t.Errorf("ReserveOrderFinalize(raced) error = %v, want ErrReserved", err)
	}

	order, err := m.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if order.Reservation == nil || order.Reservation.Token != "rival" {
		t.Errorf("reservation = %+v, want held by rival", order.Reservation)
	}
}

// Concurrent reserves of one ready order admit exactly one holder.
func TestMachineConcurrentReserves(t *testing.T) {
	t.Parallel()

	m, _ := newTestMachine(t)
	ctx := t.Context()
	createOrderRecord(t, m, &Order{ID: "o1", Status: OrderStatusReady})

	const reservers = 8
	errs := make([]error, reservers)
	var wg sync.WaitGroup
	for i := range reservers {
		wg.Go(func() {
			errs[i] = m.ReserveOrderFinalize(ctx, "o1", fmt.Sprintf("t%d", i), time.Minute)
		})
	}
	wg.Wait()

	var winners int
	for _, err := range errs {
		switch {
		case err == nil:
			winners++
		case !errors.Is(err, ErrReserved):
			t.Errorf("ReserveOrderFinalize() error = %v, want nil or ErrReserved", err)
		}
	}
	if winners != 1 {
		t.Errorf("concurrent reserve winners = %d, want 1", winners)
	}
}
