package nanoca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
	"golang.org/x/crypto/acme"
)

type accountLookupFailingStorage struct {
	nanoca.Storage
}

func (accountLookupFailingStorage) GetAccountByKey(context.Context, string) (*nanoca.Account, nanoca.Revision, error) {
	return nil, "", errors.New("backend unavailable")
}

type accountCreateRacingStorage struct {
	nanoca.Storage
	raced bool
}

func (s *accountCreateRacingStorage) CreateAccount(ctx context.Context, account *nanoca.Account) error {
	if s.raced {
		return s.Storage.CreateAccount(ctx, account)
	}
	s.raced = true

	winner := *account
	winner.ID = "concurrent-winner"
	if err := s.Storage.CreateAccount(ctx, &winner); err != nil {
		return err
	}
	return fmt.Errorf("account key already registered: %w", nanoca.ErrExists)
}

type orderLookupFailingStorage struct {
	nanoca.Storage
}

func (orderLookupFailingStorage) GetOrder(context.Context, string) (*nanoca.Order, nanoca.Revision, error) {
	return nil, "", errors.New("backend unavailable")
}

type orderCreateFailingStorage struct {
	nanoca.Storage
}

func (orderCreateFailingStorage) CreateOrder(context.Context, *nanoca.Order, []*nanoca.Authorization, []*nanoca.Challenge) error {
	return errors.New("backend unavailable")
}

type orderCreateNotFoundStorage struct {
	nanoca.Storage
}

func (orderCreateNotFoundStorage) CreateOrder(context.Context, *nanoca.Order, []*nanoca.Authorization, []*nanoca.Challenge) error {
	return fmt.Errorf("parent record missing: %w", nanoca.ErrNotFound)
}

// orderVanishingStorage drops the order once finalize has persisted it as
// valid, simulating a backend where the re-read after finalize misses.
type orderVanishingStorage struct {
	nanoca.Storage
	mu       sync.Mutex
	vanished bool
}

func (s *orderVanishingStorage) PutOrder(ctx context.Context, order *nanoca.Order, rev nanoca.Revision) error {
	err := s.Storage.PutOrder(ctx, order, rev)
	if err == nil && order.Status == nanoca.OrderStatusValid {
		s.mu.Lock()
		s.vanished = true
		s.mu.Unlock()
	}
	return err
}

func (s *orderVanishingStorage) GetOrder(ctx context.Context, id string) (*nanoca.Order, nanoca.Revision, error) {
	s.mu.Lock()
	vanished := s.vanished
	s.mu.Unlock()
	if vanished {
		return nil, "", nanoca.ErrNotFound
	}
	return s.Storage.GetOrder(ctx, id)
}

// authzLookupFailingStorage serves the challenge flow normally, then fails
// authorization lookups once armed, simulating a backend outage that begins
// between challenge validation and finalize.
type authzLookupFailingStorage struct {
	nanoca.Storage
	mu   sync.Mutex
	fail bool
}

func (s *authzLookupFailingStorage) failLookups() {
	s.mu.Lock()
	s.fail = true
	s.mu.Unlock()
}

func (s *authzLookupFailingStorage) GetAuthorization(ctx context.Context, id string) (*nanoca.Authorization, nanoca.Revision, error) {
	s.mu.Lock()
	fail := s.fail
	s.mu.Unlock()
	if fail {
		return nil, "", errors.New("backend unavailable")
	}
	return s.Storage.GetAuthorization(ctx, id)
}

// completeOrderFailingOnceStorage fails the first certificate write, after
// the certificate has been signed but before anything is persisted.
type completeOrderFailingOnceStorage struct {
	nanoca.Storage
	mu     sync.Mutex
	failed bool
}

func (s *completeOrderFailingOnceStorage) CreateCertificate(ctx context.Context, cert *nanoca.Certificate) error {
	s.mu.Lock()
	first := !s.failed
	s.failed = true
	s.mu.Unlock()
	if first {
		return errors.New("backend unavailable")
	}
	return s.Storage.CreateCertificate(ctx, cert)
}

// completionRacedStorage persists the first finalize's certificate but fails
// the order write that would commit it, leaving the certificate stored and
// referenced by no order.
type completionRacedStorage struct {
	nanoca.Storage
	mu      sync.Mutex
	certIDs []string
	armed   bool
	failed  bool
}

func (s *completionRacedStorage) CreateCertificate(ctx context.Context, cert *nanoca.Certificate) error {
	if err := s.Storage.CreateCertificate(ctx, cert); err != nil {
		return err
	}
	s.mu.Lock()
	s.certIDs = append(s.certIDs, cert.ID)
	s.armed = true
	s.mu.Unlock()
	return nil
}

func (s *completionRacedStorage) PutOrder(ctx context.Context, order *nanoca.Order, rev nanoca.Revision) error {
	s.mu.Lock()
	fail := s.armed && !s.failed
	if fail {
		s.failed = true
	}
	s.mu.Unlock()
	if fail {
		return errors.New("backend unavailable")
	}
	return s.Storage.PutOrder(ctx, order, rev)
}

type selfSignedIssuer struct{}

func (selfSignedIssuer) IssueCertificate(_ context.Context, csr *x509.CertificateRequest, _ []*nanoca.DeviceInfo) (*nanoca.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: csr.Subject}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &nanoca.Certificate{Certificate: cert, Raw: der, SerialNumber: "1"}, nil
}

type nonceConsumeFailingStorage struct {
	nanoca.Storage
}

func (nonceConsumeFailingStorage) TakeNonce(context.Context, string) (*nanoca.Nonce, error) {
	return nil, errors.New("backend unavailable")
}

func newStorageTestServer(t *testing.T, storage nanoca.Storage, issuer nanoca.CertificateIssuer) *httptest.Server {
	t.Helper()
	ts, _ := newTestServer(t, testServerConfig{issuer: issuer, storage: storage})
	return ts
}

// testReservationLease is short enough that lease-expiry tests converge
// quickly but long enough that a reservation is observably live first.
const testReservationLease = 25 * time.Millisecond

func newShortLeaseTestServer(t *testing.T, storage nanoca.Storage, issuer nanoca.CertificateIssuer) *httptest.Server {
	t.Helper()
	ts, _ := newTestServer(t, testServerConfig{
		issuer:  issuer,
		storage: storage,
		opts:    []nanoca.Option{nanoca.WithReservationLease(testReservationLease)},
	})
	return ts
}

func newFailingStorageClient(t *testing.T, storage nanoca.Storage) *acme.Client {
	t.Helper()
	return newUnregisteredClient(t, newStorageTestServer(t, storage, stubIssuer{}))
}

func wantServerInternal(t *testing.T, err error) {
	t.Helper()

	var ae *acme.Error
	if !errors.As(err, &ae) {
		t.Fatalf("error = %v, want *acme.Error", err)
	}
	if ae.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", ae.StatusCode, http.StatusInternalServerError)
	}
	if ae.ProblemType != "urn:ietf:params:acme:error:serverInternal" {
		t.Errorf("problem type = %q, want serverInternal", ae.ProblemType)
	}
}

// A storage failure during account lookup must surface as serverInternal, not
// fall through to creating a fresh account for an already-registered key.
func TestNewAccountStorageFailure(t *testing.T) {
	t.Parallel()

	client := newFailingStorageClient(t, accountLookupFailingStorage{Storage: newTestStorage(t)})

	_, err := client.Register(t.Context(), &acme.Account{}, acme.AcceptTOS)
	wantServerInternal(t, err)
}

// Losing the create race to a concurrent registration of the same key must
// return the winning account (200), not serverInternal.
func TestNewAccountCreateRace(t *testing.T) {
	t.Parallel()

	client := newFailingStorageClient(t, &accountCreateRacingStorage{Storage: newTestStorage(t)})

	_, err := client.Register(t.Context(), &acme.Account{}, acme.AcceptTOS)
	if !errors.Is(err, acme.ErrAccountAlreadyExists) {
		t.Fatalf("Register() error = %v, want ErrAccountAlreadyExists", err)
	}
	// The client adopts the Location header as its kid, so a response
	// carrying the loser's account would leave it signing with a kid the
	// server cannot resolve.
	if !strings.HasSuffix(string(client.KID), "/account/concurrent-winner") {
		t.Errorf("client KID = %q, want the winning account's URL", client.KID)
	}
}

// A storage failure while loading the order during finalize must surface as
// serverInternal; a 400 would make clients abort the order as permanently
// failed instead of retrying a transient outage.
func TestFinalizeStorageFailure(t *testing.T) {
	t.Parallel()

	client := newFailingStorageClient(t, orderLookupFailingStorage{Storage: newTestStorage(t)})
	if _, err := client.Register(t.Context(), &acme.Account{}, acme.AcceptTOS); err != nil {
		t.Fatalf("failed to register account: %v", err)
	}
	order, err := client.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "permanent-identifier", Value: "device"}})
	if err != nil {
		t.Fatalf("failed to create order: %v", err)
	}

	_, _, err = client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	wantServerInternal(t, err)
}

func TestNewOrderStorageFailure(t *testing.T) {
	t.Parallel()

	client := newFailingStorageClient(t, orderCreateFailingStorage{Storage: newTestStorage(t)})
	if _, err := client.Register(t.Context(), &acme.Account{}, acme.AcceptTOS); err != nil {
		t.Fatalf("failed to register account: %v", err)
	}

	_, err := client.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "permanent-identifier", Value: "device"}})
	wantServerInternal(t, err)
}

// The client only ever sees the generic serverInternal detail, so the
// backend error has to reach the server log or the 500 cannot be debugged.
func TestNewOrderStorageFailureLogged(t *testing.T) {
	t.Parallel()

	var logs syncBuffer
	ts, _ := newTestServer(t, testServerConfig{
		logger:  slog.New(slog.NewTextHandler(&logs, nil)),
		storage: orderCreateFailingStorage{Storage: newTestStorage(t)},
		issuer:  stubIssuer{},
	})

	client := newUnregisteredClient(t, ts)
	if _, err := client.Register(t.Context(), &acme.Account{}, acme.AcceptTOS); err != nil {
		t.Fatalf("failed to register account: %v", err)
	}
	if _, err := client.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "permanent-identifier", Value: "device"}}); err == nil {
		t.Fatal("AuthorizeOrder() error = nil, want storage failure")
	}

	if !strings.Contains(logs.String(), "backend unavailable") {
		t.Errorf("new-order failure logs omit the storage error %q:\n%s", "backend unavailable", logs.String())
	}
}

func TestFinalizeStorageFailureLogged(t *testing.T) {
	t.Parallel()

	var logs syncBuffer
	ts, _ := newTestServer(t, testServerConfig{
		logger:  slog.New(slog.NewTextHandler(&logs, nil)),
		storage: orderLookupFailingStorage{Storage: newTestStorage(t)},
		issuer:  stubIssuer{},
	})

	client := newUnregisteredClient(t, ts)
	if _, err := client.Register(t.Context(), &acme.Account{}, acme.AcceptTOS); err != nil {
		t.Fatalf("failed to register account: %v", err)
	}
	order, err := client.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "permanent-identifier", Value: "device"}})
	if err != nil {
		t.Fatalf("failed to create order: %v", err)
	}

	if _, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true); err == nil {
		t.Fatal("CreateOrderCert() error = nil, want storage failure")
	}

	if !strings.Contains(logs.String(), "backend unavailable") {
		t.Errorf("finalize failure logs omit the storage error %q:\n%s", "backend unavailable", logs.String())
	}
}

// An ErrNotFound wrapped out of CreateOrder is a backend failure, not proof
// the account is gone: accountDoesNotExist makes clients discard their
// registration and re-enroll.
func TestNewOrderCreateNotFound(t *testing.T) {
	t.Parallel()

	client := newFailingStorageClient(t, orderCreateNotFoundStorage{Storage: newTestStorage(t)})
	if _, err := client.Register(t.Context(), &acme.Account{}, acme.AcceptTOS); err != nil {
		t.Fatalf("failed to register account: %v", err)
	}

	_, err := client.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "permanent-identifier", Value: "device"}})
	wantServerInternal(t, err)
}

// Once finalize has issued and stored the certificate, the finalize response
// must not depend on re-reading the order: a miss there returns a
// permanent-looking 400 for an order that actually completed. The certificate
// fetch that follows does read the order, so with the order gone the fetch is
// refused as unauthorized; the client only attempts it because finalize
// already answered with the completed order.
func TestFinalizeSurvivesOrderRereadFailure(t *testing.T) {
	t.Parallel()

	storage := &orderVanishingStorage{Storage: newTestStorage(t)}
	ts := newStorageTestServer(t, storage, selfSignedIssuer{})

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "vanishing-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	var ae *acme.Error
	if !errors.As(err, &ae) || ae.ProblemType != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("CreateOrderCert() error = %v, want unauthorized from the certificate fetch", err)
	}
}

// A storage failure while finalize collects the verified device identity must
// fail the request: silently issuing with an empty deviceInfos strips the
// permanent-identifier/hardware-module SANs from the certificate of a device
// whose attestation already succeeded.
func TestFinalizeDeviceInfoStorageFailure(t *testing.T) {
	t.Parallel()

	storage := &authzLookupFailingStorage{Storage: newTestStorage(t)}
	ts := newStorageTestServer(t, storage, selfSignedIssuer{})

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "attested-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	storage.failLookups()
	_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	wantServerInternal(t, err)
}

// A failed completion never becomes servable: the order stays ready, so a
// retry, even with a regenerated key, gets a fresh certificate for the CSR
// it actually carries. Once the order is valid, further finalizes are
// refused per RFC 8555 Section 7.4 rather than answered with the stored
// certificate.
func TestFinalizeRetryAfterCompletionFailure(t *testing.T) {
	t.Parallel()

	storage := &completeOrderFailingOnceStorage{Storage: newTestStorage(t)}
	ts := newStorageTestServer(t, storage, selfSignedIssuer{})

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "retry-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	wantServerInternal(t, err)

	// The client regenerated its key before retrying.
	retryCSR := newCSR(t)
	chain, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, retryCSR, true)
	if err != nil {
		t.Fatalf("retried CreateOrderCert() error = %v", err)
	}
	csr, err := x509.ParseCertificateRequest(retryCSR)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	cert, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("certificate public key type = %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	if !key.Equal(csr.PublicKey) {
		t.Error("finalize returned a certificate for a different key than the submitted CSR")
	}

	_, _, err = client.CreateOrderCert(t.Context(), order.FinalizeURL, retryCSR, true)
	var ae *acme.Error
	if !errors.As(err, &ae) || ae.ProblemType != "urn:ietf:params:acme:error:orderNotReady" {
		t.Errorf("finalize after valid error = %v, want orderNotReady", err)
	}
}

// A certificate whose order write lost the completion is stored but
// referenced by no order; it must stay unservable even to the account that
// requested it, while the retry's certificate is served normally.
func TestCertificateUnreferencedByOrderNotServed(t *testing.T) {
	t.Parallel()

	storage := &completionRacedStorage{Storage: newTestStorage(t)}
	ts := newStorageTestServer(t, storage, selfSignedIssuer{})

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "zombie-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	wantServerInternal(t, err)

	_, certURL, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	if err != nil {
		t.Fatalf("retried CreateOrderCert() error = %v", err)
	}

	storage.mu.Lock()
	certIDs := slices.Clone(storage.certIDs)
	storage.mu.Unlock()
	if len(certIDs) != 2 {
		t.Fatalf("stored certificates = %d, want 2", len(certIDs))
	}

	_, err = client.FetchCert(t.Context(), ts.URL+"/certificate/"+certIDs[0], true)
	var ae *acme.Error
	if !errors.As(err, &ae) || ae.ProblemType != "urn:ietf:params:acme:error:unauthorized" {
		t.Errorf("FetchCert(unreferenced) error = %v, want unauthorized", err)
	}

	if _, err := client.FetchCert(t.Context(), certURL, true); err != nil {
		t.Errorf("FetchCert(committed) error = %v", err)
	}
}

// A nonce-storage failure must surface as serverInternal, not badNonce:
// clients respond to badNonce by retrying immediately with a fresh nonce,
// hammering a backend that is already down.
func TestNonceStorageFailure(t *testing.T) {
	t.Parallel()

	client := newFailingStorageClient(t, nonceConsumeFailingStorage{Storage: newTestStorage(t)})

	_, err := client.Register(t.Context(), &acme.Account{}, acme.AcceptTOS)
	wantServerInternal(t, err)
}

// rendezvousIssuer holds the first issuance open until a second concurrent
// call arrives (or a timeout passes), maximizing the window between the
// stored-certificate check and the certificate write.
type rendezvousIssuer struct {
	selfSignedIssuer
	mu    sync.Mutex
	calls int
	both  chan struct{}
}

func (i *rendezvousIssuer) IssueCertificate(ctx context.Context, csr *x509.CertificateRequest, infos []*nanoca.DeviceInfo) (*nanoca.Certificate, error) {
	i.mu.Lock()
	i.calls++
	if i.calls == 2 {
		close(i.both)
	}
	i.mu.Unlock()
	select {
	case <-i.both:
	case <-time.After(time.Second):
	}
	return i.selfSignedIssuer.IssueCertificate(ctx, csr, infos)
}

// Concurrent finalize POSTs for one ready order (a retry racing a slow
// first request) must not each sign a certificate: a doubled issuance
// leaves a CA-signed certificate with no storage record.
func TestFinalizeConcurrentIssuesOnce(t *testing.T) {
	t.Parallel()

	issuer := &rendezvousIssuer{both: make(chan struct{})}
	ts := newStorageTestServer(t, newTestStorage(t), issuer)

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "concurrent-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	csrs := [][]byte{newCSR(t), newCSR(t)}
	errs := make(chan error, len(csrs))
	var wg sync.WaitGroup
	for _, csr := range csrs {
		wg.Go(func() {
			_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, csr, true)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)

	failures := 0
	for err := range errs {
		if err != nil {
			failures++
			t.Logf("CreateOrderCert() error = %v", err)
		}
	}
	if failures == len(csrs) {
		t.Error("every concurrent finalize failed, want at least one success")
	}

	issuer.mu.Lock()
	calls := issuer.calls
	issuer.mu.Unlock()
	if calls != 1 {
		t.Errorf("IssueCertificate calls = %d, want 1", calls)
	}
}

// challengeRendezvousStorage, once armed, holds reads of a pending
// challenge until two concurrent readers arrive, so both duplicate POSTs
// pass the handler's pending-status guard together.
type challengeRendezvousStorage struct {
	nanoca.Storage
	mu      sync.Mutex
	armed   bool
	readers int
	both    chan struct{}
}

func (s *challengeRendezvousStorage) arm() {
	s.mu.Lock()
	s.armed = true
	s.mu.Unlock()
}

func (s *challengeRendezvousStorage) GetChallenge(ctx context.Context, id string) (*nanoca.Challenge, nanoca.Revision, error) {
	challenge, rev, err := s.Storage.GetChallenge(ctx, id)
	if err != nil || challenge.Status != nanoca.ChallengeStatusPending {
		return challenge, rev, err
	}
	s.mu.Lock()
	if !s.armed {
		s.mu.Unlock()
		return challenge, rev, nil
	}
	if s.readers < 2 {
		s.readers++
		if s.readers == 2 {
			close(s.both)
		}
	}
	s.mu.Unlock()
	select {
	case <-s.both:
	case <-time.After(2 * time.Second):
	}
	return challenge, rev, nil
}

// Duplicate challenge POSTs can also race: both read "pending" before
// either marks the challenge processing, and the loser must still get the
// current state, not a retriable 500 (TestChallengeDuplicateSubmission
// covers the sequential case).
func TestChallengeConcurrentDuplicateSubmission(t *testing.T) {
	t.Parallel()

	storage := &challengeRendezvousStorage{Storage: newTestStorage(t), both: make(chan struct{})}
	ts := newStorageTestServer(t, storage, stubIssuer{})

	client := newACMEClient(t, ts)
	_, chal := pendingChallenge(t, client, "racing-device")

	payload, err := json.Marshal(map[string]any{"attObj": nullAttObj(t)})
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	chal.Payload = payload

	storage.arm()
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			_, err := client.Accept(t.Context(), chal)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		var ae *acme.Error
		if errors.As(err, &ae) && ae.StatusCode >= http.StatusInternalServerError {
			t.Errorf("concurrent duplicate challenge POST status = %d, want non-5xx", ae.StatusCode)
		}
	}
}

// corruptAttestationStorage persists a truncated attestation, simulating a
// stored record (e.g. one written before the current format) that can no
// longer be decoded.
type corruptAttestationStorage struct {
	nanoca.Storage
}

func (s corruptAttestationStorage) PutChallenge(ctx context.Context, challenge *nanoca.Challenge, rev nanoca.Revision) error {
	if len(challenge.Attestation) > 0 {
		truncated := *challenge
		truncated.Attestation = challenge.Attestation[:1]
		return s.Storage.PutChallenge(ctx, &truncated, rev)
	}
	return s.Storage.PutChallenge(ctx, challenge, rev)
}

// An order whose stored attestation can never be re-verified is stuck: a
// 5xx invites the client to retry an operation that cannot succeed, so the
// failure must surface as a terminal problem.
func TestFinalizeUnreadableAttestationTerminal(t *testing.T) {
	t.Parallel()

	storage := corruptAttestationStorage{Storage: newTestStorage(t)}
	ts := newStorageTestServer(t, storage, selfSignedIssuer{})

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "legacy-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	var ae *acme.Error
	if !errors.As(err, &ae) {
		t.Fatalf("CreateOrderCert() error = %v, want *acme.Error", err)
	}
	if ae.StatusCode >= http.StatusInternalServerError {
		t.Errorf("finalize status = %d, want terminal non-5xx", ae.StatusCode)
	}

	// RFC 8555 Section 7.1.6: an error during finalization moves the order to
	// "invalid". Returning it to "ready" tells a polling client to submit the
	// same doomed finalize again, forever.
	got, err := client.GetOrder(t.Context(), order.URI)
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if got.Status != acme.StatusInvalid {
		t.Errorf("order status after terminal finalize failure = %q, want %q", got.Status, acme.StatusInvalid)
	}
}

// orderReadParkingStorage parks armed GetOrder calls until the test releases
// them, holding a challenge handler open between its authorization update and
// the order-status write that follows.
type orderReadParkingStorage struct {
	nanoca.Storage
	mu     sync.Mutex
	toPark int
	parked chan chan struct{}
}

func (s *orderReadParkingStorage) park(n int) {
	s.mu.Lock()
	s.toPark = n
	s.mu.Unlock()
}

func (s *orderReadParkingStorage) GetOrder(ctx context.Context, id string) (*nanoca.Order, nanoca.Revision, error) {
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
	return s.Storage.GetOrder(ctx, id)
}

// gatedIssuer holds its first issuance open so a finalize stays in flight
// until the test releases it.
type gatedIssuer struct {
	selfSignedIssuer
	mu      sync.Mutex
	calls   int
	entered chan struct{}
	release chan struct{}
}

func (i *gatedIssuer) IssueCertificate(ctx context.Context, csr *x509.CertificateRequest, infos []*nanoca.DeviceInfo) (*nanoca.Certificate, error) {
	i.mu.Lock()
	i.calls++
	first := i.calls == 1
	i.mu.Unlock()
	if first {
		close(i.entered)
		<-i.release
	}
	return i.selfSignedIssuer.IssueCertificate(ctx, csr, infos)
}

// A challenge handler's authorization-settling write that lands after a
// finalize has begun must not disturb the order: reverting it to ready mid-
// issuance discards the signed certificate, or lets a repeat finalize issue
// a second one.
func TestFinalizeReservationSurvivesAuthzUpdate(t *testing.T) {
	t.Parallel()

	storage := &orderReadParkingStorage{Storage: newTestStorage(t), parked: make(chan chan struct{}, 2)}
	issuer := &gatedIssuer{entered: make(chan struct{}), release: make(chan struct{})}
	ts := newStorageTestServer(t, storage, issuer)

	client := newACMEClient(t, ts)
	order, err := client.AuthorizeOrder(t.Context(), []acme.AuthzID{
		{Type: "permanent-identifier", Value: "device-a"},
		{Type: "permanent-identifier", Value: "device-b"},
	})
	if err != nil {
		t.Fatalf("failed to create order: %v", err)
	}

	payload, err := json.Marshal(map[string]any{"attObj": nullAttObj(t)})
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	storage.park(2)
	posted := make(chan error, 2)
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(t.Context(), authzURL)
		if err != nil {
			t.Fatalf("failed to get authorization: %v", err)
		}
		chal := authz.Challenges[0]
		chal.Payload = payload
		go func() {
			_, err := client.Accept(t.Context(), chal)
			posted <- err
		}()
	}

	// Both handlers have committed their authorization valid and are parked
	// before reading the order; releasing one moves the order to ready.
	gate1 := <-storage.parked
	gate2 := <-storage.parked
	close(gate1)
	if err := <-posted; err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	csr := newCSR(t)
	finalized := make(chan error, 1)
	go func() {
		_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, csr, true)
		finalized <- err
	}()
	<-issuer.entered

	// The reservation is now held; the parked handler commits its stale
	// order-status write before issuance completes.
	close(gate2)
	if err := <-posted; err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}
	close(issuer.release)

	if err := <-finalized; err != nil {
		t.Errorf("CreateOrderCert() error = %v, want success despite concurrent authorization update", err)
	}
}

// RFC 8555 Section 7.4: "processing" tells a polling client the certificate
// is being issued and to poll again; "ready" tells it to submit a finalize,
// which during issuance would only draw 403 orderNotReady.
func TestOrderPollsProcessingDuringFinalize(t *testing.T) {
	t.Parallel()

	issuer := &gatedIssuer{entered: make(chan struct{}), release: make(chan struct{})}
	ts := newStorageTestServer(t, newTestStorage(t), issuer)

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "polling-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	csr := newCSR(t)
	finalized := make(chan error, 1)
	go func() {
		_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, csr, true)
		finalized <- err
	}()
	<-issuer.entered

	polled, err := client.GetOrder(t.Context(), order.URI)
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if polled.Status != acme.StatusProcessing {
		t.Errorf("order status during finalize = %q, want %q", polled.Status, acme.StatusProcessing)
	}

	close(issuer.release)
	if err := <-finalized; err != nil {
		t.Fatalf("CreateOrderCert() error = %v", err)
	}
}

// orderWriteFailingStorage fails unreserved order writes while armed,
// simulating a backend outage that also takes out any cleanup write a
// failing finalize attempts. Writes that record a reservation still land,
// so the outage begins after the reserve.
type orderWriteFailingStorage struct {
	nanoca.Storage
	mu   sync.Mutex
	fail bool
}

func (s *orderWriteFailingStorage) setFail(fail bool) {
	s.mu.Lock()
	s.fail = fail
	s.mu.Unlock()
}

func (s *orderWriteFailingStorage) failing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fail
}

func (s *orderWriteFailingStorage) PutOrder(ctx context.Context, order *nanoca.Order, rev nanoca.Revision) error {
	if s.failing() && order.Reservation == nil {
		return errors.New("backend unavailable")
	}
	return s.Storage.PutOrder(ctx, order, rev)
}

// failOnceIssuer fails the first issuance, as during a transient outage.
type failOnceIssuer struct {
	selfSignedIssuer
	mu     sync.Mutex
	failed bool
}

func (i *failOnceIssuer) IssueCertificate(ctx context.Context, csr *x509.CertificateRequest, infos []*nanoca.DeviceInfo) (*nanoca.Certificate, error) {
	i.mu.Lock()
	first := !i.failed
	i.failed = true
	i.mu.Unlock()
	if first {
		return nil, errors.New("issuer unavailable")
	}
	return i.selfSignedIssuer.IssueCertificate(ctx, csr, infos)
}

// A finalize that fails during a backend outage must not wedge the order in
// an intermediate state: the failed release leaves it processing, so once
// storage heals a retry has to be able to reclaim the lapsed reservation and
// finalize instead of drawing 403 orderNotReady forever.
func TestFinalizeRecoversAfterRollbackFailure(t *testing.T) {
	t.Parallel()

	storage := &orderWriteFailingStorage{Storage: newTestStorage(t)}
	ts := newShortLeaseTestServer(t, storage, &failOnceIssuer{})

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "outage-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	storage.setFail(true)
	_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	wantServerInternal(t, err)
	storage.setFail(false)

	deadline := time.Now().Add(10 * time.Second)
	for {
		_, _, err = client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Errorf("retried CreateOrderCert() after outage error = %v, want success", err)
	}
}

// challengeValidFailingOnceStorage fails the first valid settlement,
// stranding a verified challenge in "processing" under a live reservation
// the way a crash between the reserve and the terminal write would.
type challengeValidFailingOnceStorage struct {
	nanoca.Storage
	mu     sync.Mutex
	failed bool
}

func (s *challengeValidFailingOnceStorage) PutChallenge(ctx context.Context, challenge *nanoca.Challenge, rev nanoca.Revision) error {
	if challenge.Status == nanoca.ChallengeStatusValid {
		s.mu.Lock()
		first := !s.failed
		s.failed = true
		s.mu.Unlock()
		if first {
			return errors.New("backend unavailable")
		}
	}
	return s.Storage.PutChallenge(ctx, challenge, rev)
}

// A challenge left in "processing" by an interrupted validation has no owner:
// nothing retries it in the background, and re-submissions within the lease
// are answered with 200 {"status":"processing"}. Once the lease lapses, the
// client must be able to reclaim it and drive it to a terminal state, or its
// order is silently wedged.
func TestChallengeRecoversFromInterruptedValidation(t *testing.T) {
	t.Parallel()

	storage := &challengeValidFailingOnceStorage{Storage: newTestStorage(t)}
	ts := newShortLeaseTestServer(t, storage, selfSignedIssuer{})

	client := newACMEClient(t, ts)
	_, chal := pendingChallenge(t, client, "interrupted-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err == nil {
		t.Fatal("Accept() error = nil, want failure from interrupted validation")
	}

	deadline := time.Now().Add(10 * time.Second)
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
			t.Fatalf("challenge status after re-submissions = %q, want %q", got.Status, acme.StatusValid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A finalize POST from an account that does not own the order must be turned
// away before it takes the order's finalize reservation: while a foreign
// request holds it, the owner draws 403 orderNotReady from its own finalize
// and sees the order polling as "processing".
func TestFinalizeForeignAccountDoesNotReserveOrder(t *testing.T) {
	t.Parallel()

	storage := &orderReadParkingStorage{Storage: newTestStorage(t), parked: make(chan chan struct{}, 1)}
	ts := newStorageTestServer(t, storage, selfSignedIssuer{})

	owner := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, owner, "owned-device")
	if err := submitAttObj(t, owner, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	intruder := newACMEClient(t, ts)
	intruderCSR := newCSR(t)
	storage.park(1)
	finalized := make(chan error, 1)
	go func() {
		_, _, err := intruder.CreateOrderCert(t.Context(), order.FinalizeURL, intruderCSR, true)
		finalized <- err
	}()

	// The intruder's finalize is parked reading the order.
	gate := <-storage.parked
	release := sync.OnceFunc(func() { close(gate) })
	defer release()

	polled, err := owner.GetOrder(t.Context(), order.URI)
	if err != nil {
		t.Errorf("GetOrder() error = %v", err)
	} else if polled.Status != acme.StatusReady {
		t.Errorf("order status during foreign finalize = %q, want %q", polled.Status, acme.StatusReady)
	}

	if _, _, err := owner.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true); err != nil {
		t.Errorf("owner CreateOrderCert() error = %v, want success", err)
	}

	release()
	var ae *acme.Error
	if err := <-finalized; !errors.As(err, &ae) || ae.ProblemType != "urn:ietf:params:acme:error:unauthorized" {
		t.Errorf("intruder CreateOrderCert() error = %v, want unauthorized", err)
	}
}

// challengeValidRacedStorage simulates another CA instance completing the
// challenge between our processing transition and the terminal write: the
// rival's settle lands first, so our conditional write conflicts and the
// re-read finds the challenge already valid.
type challengeValidRacedStorage struct {
	nanoca.Storage
	mu    sync.Mutex
	raced bool
}

func (s *challengeValidRacedStorage) PutChallenge(ctx context.Context, challenge *nanoca.Challenge, rev nanoca.Revision) error {
	if challenge.Status == nanoca.ChallengeStatusValid {
		s.mu.Lock()
		race := !s.raced
		s.raced = true
		s.mu.Unlock()
		if race {
			stored, storedRev, err := s.GetChallenge(ctx, challenge.ID)
			if err != nil {
				return err
			}
			now := time.Now()
			stored.Status = nanoca.ChallengeStatusValid
			stored.Validated = &now
			stored.Reservation = nil
			if err := s.Storage.PutChallenge(ctx, stored, storedRev); err != nil {
				return err
			}
		}
	}
	return s.Storage.PutChallenge(ctx, challenge, rev)
}

// Losing the terminal write to a concurrent validation is the same
// client-state condition the reserve path reports with the challenge's
// current state; a 500 invites the client to retry a challenge that has
// already succeeded.
func TestChallengeValidStatusMismatchReportsState(t *testing.T) {
	t.Parallel()

	storage := &challengeValidRacedStorage{Storage: newTestStorage(t)}
	ts := newStorageTestServer(t, storage, stubIssuer{})

	client := newACMEClient(t, ts)
	_, chal := pendingChallenge(t, client, "raced-device")

	err := submitAttObj(t, client, chal, nullAttObj(t))
	var ae *acme.Error
	if errors.As(err, &ae) && ae.StatusCode >= http.StatusInternalServerError {
		t.Errorf("raced challenge POST status = %d, want non-5xx", ae.StatusCode)
	}
}

// orderStatusRacedStorage lands the same transition through a rival write
// first, so the guarded transition loses its conditional write and the
// re-read finds the work already done.
type orderStatusRacedStorage struct {
	nanoca.Storage
	mu    sync.Mutex
	raced bool
}

func (s *orderStatusRacedStorage) PutOrder(ctx context.Context, order *nanoca.Order, rev nanoca.Revision) error {
	s.mu.Lock()
	race := !s.raced
	s.raced = true
	s.mu.Unlock()
	if race {
		stored, storedRev, err := s.GetOrder(ctx, order.ID)
		if err != nil {
			return err
		}
		stored.Status = order.Status
		if err := s.Storage.PutOrder(ctx, stored, storedRev); err != nil {
			return err
		}
	}
	return s.Storage.PutOrder(ctx, order, rev)
}

// updateOrderStatus tolerates losing the transition race, but it must not
// log a status change that never happened.
func TestOrderStatusChangeLoggedOnlyOnTransition(t *testing.T) {
	t.Parallel()

	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ts, _ := newTestServer(t, testServerConfig{logger: logger, issuer: stubIssuer{}, storage: &orderStatusRacedStorage{Storage: newTestStorage(t)}})

	client := newACMEClient(t, ts)
	_, chal := pendingChallenge(t, client, "settled-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	if strings.Contains(logs.String(), "Order status changed") {
		t.Errorf("logs claim an order status change that was rejected:\n%s", logs.String())
	}
}

// A finalize whose lease lapses while it is still signing must not persist
// its certificate over the reclaiming retry's: the stored certificate has to
// answer the CSR of the finalize that holds the reservation.
func TestFinalizeZombieCannotPersistStaleCSR(t *testing.T) {
	t.Parallel()

	issuer := &gatedIssuer{entered: make(chan struct{}), release: make(chan struct{})}
	ts := newShortLeaseTestServer(t, newTestStorage(t), issuer)

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "zombie-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	zombieCSR := newCSR(t)
	zombieDone := make(chan error, 1)
	go func() {
		_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, zombieCSR, true)
		zombieDone <- err
	}()
	<-issuer.entered

	// The zombie is parked inside IssueCertificate; retry with a fresh CSR
	// until its lease lapses and the reservation is reclaimed.
	retryCSR := newCSR(t)
	var chain [][]byte
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for {
		chain, _, err = client.CreateOrderCert(t.Context(), order.FinalizeURL, retryCSR, true)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("reclaiming CreateOrderCert() error = %v", err)
	}

	close(issuer.release)
	if err := <-zombieDone; err == nil {
		t.Error("zombie CreateOrderCert() error = nil, want failure after reclaim")
	}

	csr, err := x509.ParseCertificateRequest(retryCSR)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	cert, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("certificate public key type = %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	if !key.Equal(csr.PublicKey) {
		t.Error("stored certificate does not answer the reservation holder's CSR")
	}
}

// An order abandoned mid-finalize by a dead CA instance sits processing in
// storage; once the reservation lapses, polls must report ready — telling an
// RFC 8555 Section 7.1.6 client to re-submit — and the re-submitted finalize
// must reclaim and complete.
func TestOrderRecoversFromAbandonedReservation(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	ts := newShortLeaseTestServer(t, storage, selfSignedIssuer{})

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "abandoned-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	// A dead CA instance left the order processing under its reservation.
	orderID := path.Base(order.URI)
	abandoned, rev, err := storage.GetOrder(t.Context(), orderID)
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	abandoned.Status = nanoca.OrderStatusProcessing
	abandoned.Reservation = &nanoca.Reservation{Token: "dead-instance", ReservedAt: time.Now()}
	if err := storage.PutOrder(t.Context(), abandoned, rev); err != nil {
		t.Fatalf("PutOrder() error = %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		polled, err := client.GetOrder(t.Context(), order.URI)
		if err != nil {
			t.Fatalf("GetOrder() error = %v", err)
		}
		if polled.Status == acme.StatusReady {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("order status = %q, want %q after reservation lapse", polled.Status, acme.StatusReady)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true); err != nil {
		t.Errorf("CreateOrderCert() after abandoned reservation error = %v, want success", err)
	}
}

// authzDemotingStorage, once armed, reports every authorization as pending,
// so a finalize observes a ready order whose authorization no longer reads
// valid — the state a stale authorization write leaves behind.
type authzDemotingStorage struct {
	nanoca.Storage
	mu    sync.Mutex
	armed bool
}

func (s *authzDemotingStorage) arm() {
	s.mu.Lock()
	s.armed = true
	s.mu.Unlock()
}

func (s *authzDemotingStorage) GetAuthorization(ctx context.Context, id string) (*nanoca.Authorization, nanoca.Revision, error) {
	authz, rev, err := s.Storage.GetAuthorization(ctx, id)
	if err != nil {
		return nil, "", err
	}
	s.mu.Lock()
	armed := s.armed
	s.mu.Unlock()
	if armed {
		authz.Status = nanoca.AuthzStatusPending
	}
	return authz, rev, nil
}

// The order only reached ready through a valid authorization, so a
// finalize that cannot re-derive the attested identity must abort rather
// than mint a certificate with the permanent-identifier/hardware-module
// SANs silently stripped.
func TestFinalizeRefusesOrderWithoutValidAuthz(t *testing.T) {
	t.Parallel()

	storage := &authzDemotingStorage{Storage: newTestStorage(t)}
	ts := newStorageTestServer(t, storage, nil)

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "demoted-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	storage.arm()
	chain, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	if err != nil {
		return
	}

	cert, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(sanOID) {
			return
		}
	}
	t.Error("finalize issued a certificate without the attested identifiers")
}

// The stored authorization names its challenges by ID; reads compose the
// wire-format challenges from the challenge records, so a settled
// authorization always reflects the live challenge state.
func TestSettledAuthorizationComposesChallenges(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	ts := newStorageTestServer(t, storage, nil)

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "composed-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	stored, _, err := storage.GetAuthorization(t.Context(), path.Base(order.AuthzURLs[0]))
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}
	if stored.Status != nanoca.AuthzStatusValid {
		t.Fatalf("authorization status = %q, want %q", stored.Status, nanoca.AuthzStatusValid)
	}
	if len(stored.ChallengeIDs) != 1 {
		t.Fatalf("stored challenge IDs = %v, want one", stored.ChallengeIDs)
	}
	if len(stored.Challenges) != 0 {
		t.Errorf("stored authorization embeds %d challenge copies, want none", len(stored.Challenges))
	}

	wire, err := client.GetAuthorization(t.Context(), order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("client GetAuthorization() error = %v", err)
	}
	if len(wire.Challenges) != 1 || wire.Challenges[0].Status != acme.StatusValid {
		t.Errorf("wire challenges = %+v, want one valid challenge", wire.Challenges)
	}
}

// completeOrderRacedStorage simulates a zombie finalize whose lease lapsed
// mid-issuance: a rival reclaims the reservation before the completion
// write lands, so the write conflicts and the re-read finds the
// reservation held by another token.
type completeOrderRacedStorage struct {
	nanoca.Storage
	mu    sync.Mutex
	raced bool
}

func (s *completeOrderRacedStorage) PutOrder(ctx context.Context, order *nanoca.Order, rev nanoca.Revision) error {
	if order.Status == nanoca.OrderStatusValid {
		s.mu.Lock()
		race := !s.raced
		s.raced = true
		s.mu.Unlock()
		if race {
			stored, storedRev, err := s.GetOrder(ctx, order.ID)
			if err != nil {
				return err
			}
			stored.Reservation = &nanoca.Reservation{Token: "rival", ReservedAt: time.Now()}
			if err := s.Storage.PutOrder(ctx, stored, storedRev); err != nil {
				return err
			}
		}
	}
	return s.Storage.PutOrder(ctx, order, rev)
}

// Losing the finalize reservation to a reclaiming retry is the same
// client-state condition the reserve path answers with 403 orderNotReady
// and the challenge path answers with the current state; a 500 invites the
// client to retry a finalize that has already been superseded.
func TestFinalizeCompletionRaceNonRetriable(t *testing.T) {
	t.Parallel()

	storage := &completeOrderRacedStorage{Storage: newTestStorage(t)}
	ts := newStorageTestServer(t, storage, selfSignedIssuer{})

	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "reclaimed-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	var ae *acme.Error
	if !errors.As(err, &ae) {
		t.Fatalf("CreateOrderCert() error = %v, want *acme.Error", err)
	}
	if ae.StatusCode >= http.StatusInternalServerError {
		t.Errorf("finalize after lost completion race status = %d, want non-5xx", ae.StatusCode)
	}
}
