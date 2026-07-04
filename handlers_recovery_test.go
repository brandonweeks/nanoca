package nanoca_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/acme"
)

func attObjFor(t *testing.T, format string) string {
	t.Helper()
	b, err := cbor.Marshal(map[string]any{"fmt": format, "attStmt": map[string]any{}})
	if err != nil {
		t.Fatalf("failed to marshal attestation: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// gateVerifier scripts two validations of one challenge: the first (a
// zombie whose lease will lapse) blocks until released and fails, the
// second (the reclaiming retry) blocks until released and succeeds.
type gateVerifier struct {
	mu      sync.Mutex
	calls   int
	entered [2]chan struct{}
	release [2]chan struct{}
}

func newGateVerifier() *gateVerifier {
	return &gateVerifier{
		entered: [2]chan struct{}{make(chan struct{}), make(chan struct{})},
		release: [2]chan struct{}{make(chan struct{}), make(chan struct{})},
	}
}

func (v *gateVerifier) Format() string { return "gate" }

func (v *gateVerifier) Verify(context.Context, nanoca.AttestationStatement, []byte) (*nanoca.DeviceInfo, error) {
	v.mu.Lock()
	call := v.calls
	v.calls++
	v.mu.Unlock()
	if call < 2 {
		close(v.entered[call])
		<-v.release[call]
	}
	if call == 0 {
		return nil, errors.New("verifier unavailable")
	}
	return &nanoca.DeviceInfo{
		PermanentIdentifier: &nanoca.PermanentIdentifier{Identifier: "gate-device"},
	}, nil
}

// authzWriteParkingStorage parks armed SettleAuthorization calls until the
// test releases them, so a stale authorization write can be made to land
// after a newer one.
type authzWriteParkingStorage struct {
	nanoca.Storage
	mu     sync.Mutex
	toPark int
	parked chan chan struct{}
}

func (s *authzWriteParkingStorage) park(n int) {
	s.mu.Lock()
	s.toPark = n
	s.mu.Unlock()
}

func (s *authzWriteParkingStorage) SettleAuthorization(ctx context.Context, authz *nanoca.Authorization) error {
	s.mu.Lock()
	if s.toPark > 0 {
		s.toPark--
		s.mu.Unlock()
		gate := make(chan struct{})
		s.parked <- gate
		<-gate
	} else {
		s.mu.Unlock()
	}
	return s.Storage.SettleAuthorization(ctx, authz)
}

// A zombie validation whose invalid settlement is rejected has no
// claim left on the challenge, yet it still recomputes the authorization.
// Its stale write must not revert an authorization a reclaiming retry has
// settled valid: with the order already ready, a reverted authorization is
// skipped by finalize's device-info collection and the certificate is
// issued without the attested identifiers.
func TestZombieInvalidationDoesNotRevertSettledAuthz(t *testing.T) {
	t.Parallel()

	verifier := newGateVerifier()
	storage := &authzWriteParkingStorage{Storage: newTestStorage(t), parked: make(chan chan struct{}, 1)}
	ts, _ := newTestServer(t, testServerConfig{
		storage:   storage,
		opts:      []nanoca.Option{nanoca.WithReservationLease(testReservationLease)},
		verifiers: []nanoca.AttestationVerifier{verifier},
	})

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "zombie-authz-device")

	payload, err := json.Marshal(map[string]any{"attObj": attObjFor(t, "gate")})
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	chal.Payload = payload

	zombieDone := make(chan error, 1)
	go func() {
		_, err := client.Accept(t.Context(), chal)
		zombieDone <- err
	}()
	<-verifier.entered[0]

	// The zombie holds the reservation inside its verifier; once the lease
	// lapses, the retry reclaims it and parks inside its own verifier.
	time.Sleep(2 * testReservationLease)
	retryDone := make(chan error, 1)
	go func() {
		_, err := client.Accept(t.Context(), chal)
		retryDone <- err
	}()
	<-verifier.entered[1]

	// The zombie fails verification while the retry holds the reservation,
	// so its invalid settlement is rejected. If it goes on to
	// recompute the authorization anyway, its stale write parks; if it
	// stops at the rejected write, it finishes without writing.
	storage.park(1)
	close(verifier.release[0])
	var gate chan struct{}
	select {
	case gate = <-storage.parked:
	case <-zombieDone:
		storage.park(0)
	}

	close(verifier.release[1])
	if err := <-retryDone; err != nil {
		t.Fatalf("reclaiming Accept() error = %v, want success", err)
	}

	// The retry has settled: challenge valid, authorization valid, order
	// ready. Any parked zombie write lands last.
	if gate != nil {
		close(gate)
		<-zombieDone
	}

	authz, err := client.GetAuthorization(t.Context(), order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}
	if authz.Status != acme.StatusValid {
		t.Errorf("authorization status after zombie write = %q, want %q", authz.Status, acme.StatusValid)
	}
}

// A validation interrupted between the reserve and the terminal write
// leaves the challenge processing with no owner. RFC 8555 Section 7.1.6
// clients respond to a challenge once and then poll — they never re-POST
// the attestation — so once the lease lapses a poll must present the
// challenge as pending again, the way handleOrder re-presents a lapsed
// processing order as ready, or the order wedges for polling clients.
func TestStrandedChallengeRecoversByPolling(t *testing.T) {
	t.Parallel()

	storage := &challengeValidFailingOnceStorage{Storage: newTestStorage(t)}
	ts := newShortLeaseTestServer(t, storage, nil)

	client := newACMEClient(t, ts)
	_, chal := pendingChallenge(t, client, "poll-only-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err == nil {
		t.Fatal("Accept() error = nil, want failure from interrupted validation")
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		got, err := client.GetChallenge(t.Context(), chal.URI)
		if err != nil {
			t.Fatalf("GetChallenge() error = %v", err)
		}
		if got.Status == acme.StatusPending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("challenge status polled after abandoned validation = %q, want %q", got.Status, acme.StatusPending)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type failOnceAuthorizer struct {
	mu     sync.Mutex
	failed bool
}

func (a *failOnceAuthorizer) Authorize(context.Context, *nanoca.DeviceInfo) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.failed {
		a.failed = true
		return false, errors.New("authorizer unavailable")
	}
	return true, nil
}

// An authorizer error is a backend condition (the ABM authorizer calls a
// network API), and failOrder keeps 5xx-class finalize failures retriable
// for exactly that reason. A one-off authorizer outage must not durably
// invalidate the challenge — and with it the authorization and order —
// when a retry after the outage would succeed.
func TestChallengeSurvivesTransientAuthorizerError(t *testing.T) {
	t.Parallel()

	ts, _ := newTestServer(t, testServerConfig{authorizer: &failOnceAuthorizer{}})
	client := newACMEClient(t, ts)

	_, chal := pendingChallenge(t, client, "authz-outage-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err == nil {
		t.Fatal("Accept() error = nil, want failure from authorizer outage")
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		_ = submitAttObj(t, client, chal, nullAttObj(t))
		got, err := client.GetChallenge(t.Context(), chal.URI)
		if err != nil {
			t.Fatalf("GetChallenge() error = %v", err)
		}
		if got.Status == acme.StatusValid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("challenge status after authorizer recovery = %q, want %q", got.Status, acme.StatusValid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// flakyReverifyVerifier succeeds at challenge time, fails once at finalize
// re-verification, then succeeds again — a pluggable verifier that does
// I/O (revocation fetch, TPM CA lookup) behaves this way during a
// transient outage.
type flakyReverifyVerifier struct {
	mu    sync.Mutex
	calls int
}

func (v *flakyReverifyVerifier) Format() string { return "flaky" }

func (v *flakyReverifyVerifier) Verify(context.Context, nanoca.AttestationStatement, []byte) (*nanoca.DeviceInfo, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	if v.calls == 2 {
		return nil, errors.New("verifier unavailable")
	}
	return &nanoca.DeviceInfo{
		PermanentIdentifier: &nanoca.PermanentIdentifier{Identifier: "flaky-device"},
	}, nil
}

// The order only reached ready through a successful attestation, so a
// transient re-verification failure at finalize can clear on retry; moving
// the order to invalid forces the device to restart enrollment for a
// failure it did not cause.
func TestFinalizeRetryAfterTransientVerifierError(t *testing.T) {
	t.Parallel()

	ts, _ := newTestServer(t, testServerConfig{verifiers: []nanoca.AttestationVerifier{&flakyReverifyVerifier{}}})
	client := newACMEClient(t, ts)

	order, chal := pendingChallenge(t, client, "flaky-verify-device")
	if err := submitAttObj(t, client, chal, attObjFor(t, "flaky")); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	if _, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true); err == nil {
		t.Fatal("CreateOrderCert() error = nil, want re-verification failure")
	}

	deadline := time.Now().Add(3 * time.Second)
	var err error
	for {
		_, _, err = client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Errorf("retried CreateOrderCert() after transient verifier error = %v, want success", err)
	}
}

// Once the authorization is valid, promoting the order must not hinge on a
// single SetOrderStatus write succeeding: re-POSTs of the valid challenge
// short-circuit before recomputing, and updateAuthorizationStatus returns
// early on the settled authorization, so nothing ever retries the
// pending-to-ready transition and the order polls pending forever.
func TestOrderReadyRetriesAfterStatusWriteFailure(t *testing.T) {
	t.Parallel()

	storage := &orderWriteFailingStorage{Storage: newTestStorage(t)}
	ts := newStorageTestServer(t, storage, nil)

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "promotion-device")

	storage.setFail(true)
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}
	storage.setFail(false)

	deadline := time.Now().Add(3 * time.Second)
	for {
		_ = submitAttObj(t, client, chal, nullAttObj(t))
		polled, err := client.GetOrder(t.Context(), order.URI)
		if err != nil {
			t.Fatalf("GetOrder() error = %v", err)
		}
		if polled.Status == acme.StatusReady {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("order status after storage heals = %q, want %q", polled.Status, acme.StatusReady)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// challengeInvalidFailingStorage fails the invalid settlement with a plain
// backend error while armed, so failChallenge takes its backend-error branch
// and never learns another request has claimed the challenge.
type challengeInvalidFailingStorage struct {
	nanoca.Storage
	mu    sync.Mutex
	armed bool
}

func (s *challengeInvalidFailingStorage) arm() {
	s.mu.Lock()
	s.armed = true
	s.mu.Unlock()
}

func (s *challengeInvalidFailingStorage) SettleChallenge(ctx context.Context, challenge *nanoca.Challenge, reservationToken string) error {
	s.mu.Lock()
	armed := s.armed
	s.mu.Unlock()
	if armed && challenge.Status == nanoca.ChallengeStatusInvalid {
		return errors.New("backend unavailable")
	}
	return s.Storage.SettleChallenge(ctx, challenge, reservationToken)
}

// A zombie can also lose its claim without being told: when its invalid
// settlement fails with a backend error instead of a token rejection, it
// goes on to recompute the authorization from reads taken
// before the reclaiming retry settled. That stale write must not revert
// the settled authorization any more than the token-rejection variant
// (TestZombieInvalidationDoesNotRevertSettledAuthz) may.
func TestZombieBackendErrorDoesNotRevertSettledAuthz(t *testing.T) {
	t.Parallel()

	verifier := newGateVerifier()
	failing := &challengeInvalidFailingStorage{Storage: newTestStorage(t)}
	storage := &authzWriteParkingStorage{Storage: failing, parked: make(chan chan struct{}, 1)}
	ts, _ := newTestServer(t, testServerConfig{
		storage:   storage,
		opts:      []nanoca.Option{nanoca.WithReservationLease(testReservationLease)},
		verifiers: []nanoca.AttestationVerifier{verifier},
	})

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "zombie-backend-device")

	payload, err := json.Marshal(map[string]any{"attObj": attObjFor(t, "gate")})
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	chal.Payload = payload

	zombieDone := make(chan error, 1)
	go func() {
		_, err := client.Accept(t.Context(), chal)
		zombieDone <- err
	}()
	<-verifier.entered[0]

	// The zombie holds the reservation inside its verifier; once the lease
	// lapses, the retry reclaims it and parks inside its own verifier.
	time.Sleep(2 * testReservationLease)
	retryDone := make(chan error, 1)
	go func() {
		_, err := client.Accept(t.Context(), chal)
		retryDone <- err
	}()
	<-verifier.entered[1]

	// The zombie fails verification while the retry holds the reservation,
	// but its settle write reports a backend error, not the token
	// rejection. If it recomputes the authorization anyway, its stale
	// write parks; if it treats the lost claim as settled, it finishes
	// without writing.
	failing.arm()
	storage.park(1)
	close(verifier.release[0])
	var gate chan struct{}
	select {
	case gate = <-storage.parked:
	case <-zombieDone:
		storage.park(0)
	}

	close(verifier.release[1])
	if err := <-retryDone; err != nil {
		t.Fatalf("reclaiming Accept() error = %v, want success", err)
	}

	// The retry has settled: challenge valid, authorization valid, order
	// ready. Any parked zombie write lands last.
	if gate != nil {
		close(gate)
		<-zombieDone
	}

	authz, err := client.GetAuthorization(t.Context(), order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}
	if authz.Status != acme.StatusValid {
		t.Errorf("authorization status after zombie write = %q, want %q", authz.Status, acme.StatusValid)
	}
}

// authzSettleFailingStorage fails authorization settles while armed,
// simulating a backend outage that begins between a challenge's terminal
// write and the authorization promotion that follows.
type authzSettleFailingStorage struct {
	nanoca.Storage
	mu   sync.Mutex
	fail bool
}

func (s *authzSettleFailingStorage) setFail(fail bool) {
	s.mu.Lock()
	s.fail = fail
	s.mu.Unlock()
}

func (s *authzSettleFailingStorage) SettleAuthorization(ctx context.Context, authz *nanoca.Authorization) error {
	s.mu.Lock()
	fail := s.fail
	s.mu.Unlock()
	if fail {
		return errors.New("backend unavailable")
	}
	return s.Storage.SettleAuthorization(ctx, authz)
}

// Once the challenge is valid, promoting the authorization must not hinge
// on a single settle write succeeding: re-POSTs of the valid challenge
// short-circuit the validation path, and order polls recompute only from
// the authorization's stored status, so without a retry hook the order
// wedges — the same trap the order leg escapes in
// TestOrderReadyRetriesAfterStatusWriteFailure.
func TestAuthzPromotionRetriesAfterWriteFailure(t *testing.T) {
	t.Parallel()

	storage := &authzSettleFailingStorage{Storage: newTestStorage(t)}
	ts := newStorageTestServer(t, storage, nil)

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "authz-promotion-device")

	storage.setFail(true)
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}
	storage.setFail(false)

	deadline := time.Now().Add(3 * time.Second)
	for {
		_ = submitAttObj(t, client, chal, nullAttObj(t))
		polled, err := client.GetOrder(t.Context(), order.URI)
		if err != nil {
			t.Fatalf("GetOrder() error = %v", err)
		}
		if polled.Status == acme.StatusReady {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("order status after storage heals = %q, want %q", polled.Status, acme.StatusReady)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An RFC 8555 Section 7.5.1 client watches the authorization object, not the
// challenge URL — x/crypto/acme's WaitAuthorization never re-reads the
// challenge directly. The lease-lapse presentation handleChallenge applies
// must therefore reach the authorization view too: a challenge stranded in
// processing by an interrupted validation has to read as pending in the
// embedded copy once the lease lapses, or authorization-polling clients
// wedge forever (TestStrandedChallengeRecoversByPolling covers the
// challenge-URL leg).
func TestStrandedChallengeRecoversByAuthzPolling(t *testing.T) {
	t.Parallel()

	storage := &challengeValidFailingOnceStorage{Storage: newTestStorage(t)}
	ts := newShortLeaseTestServer(t, storage, nil)

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "authz-poll-only-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err == nil {
		t.Fatal("Accept() error = nil, want failure from interrupted validation")
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		authz, err := client.GetAuthorization(t.Context(), order.AuthzURLs[0])
		if err != nil {
			t.Fatalf("GetAuthorization() error = %v", err)
		}
		if authz.Challenges[0].Status == acme.StatusPending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("challenge status in polled authorization after abandoned validation = %q, want %q",
				authz.Challenges[0].Status, acme.StatusPending)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
