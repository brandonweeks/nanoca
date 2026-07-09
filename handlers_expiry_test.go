package nanoca_test

import (
	"context"
	"crypto/x509"
	"errors"
	"path"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
	"golang.org/x/crypto/acme"
)

func expireOrder(t *testing.T, s nanoca.Storage, orderURL string) {
	t.Helper()
	order, rev, err := s.GetOrder(t.Context(), path.Base(orderURL))
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	past := time.Now().Add(-time.Minute)
	order.Expires = &past
	if err := s.PutOrder(t.Context(), order, rev); err != nil {
		t.Fatalf("PutOrder() error = %v", err)
	}
}

func expireAuthorization(t *testing.T, s nanoca.Storage, authzURL string) {
	t.Helper()
	authz, rev, err := s.GetAuthorization(t.Context(), path.Base(authzURL))
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}
	past := time.Now().Add(-time.Minute)
	authz.Expires = &past
	if err := s.PutAuthorization(t.Context(), authz, rev); err != nil {
		t.Fatalf("PutAuthorization() error = %v", err)
	}
}

// RFC 8555 Section 7.1.3 requires expires on pending orders, and Section
// 7.1.6 moves an order that outlives it to invalid.
func TestExpiredOrderPollsInvalid(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	ts, _ := newTestServer(t, testServerConfig{storage: storage})
	client := newACMEClient(t, ts)

	order, _ := pendingChallenge(t, client, "expiring-device")
	if order.Expires.IsZero() {
		t.Error("new order carries no expires")
	}

	expireOrder(t, storage, order.URI)

	got, err := client.GetOrder(t.Context(), order.URI)
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if got.Status != acme.StatusInvalid {
		t.Errorf("expired order status = %q, want %q", got.Status, acme.StatusInvalid)
	}
}

// An expired order is no longer ready, so finalize is refused before any
// reservation is taken and no certificate is issued.
func TestFinalizeExpiredOrder(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	ts, _ := newTestServer(t, testServerConfig{storage: storage})
	client := newACMEClient(t, ts)

	order, chal := pendingChallenge(t, client, "expired-finalize-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	expireOrder(t, storage, order.URI)

	_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	var ae *acme.Error
	if !errors.As(err, &ae) || ae.ProblemType != "urn:ietf:params:acme:error:orderNotReady" {
		t.Errorf("finalize of expired order error = %v, want orderNotReady", err)
	}

	got, err := client.GetOrder(t.Context(), order.URI)
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if got.CertURL != "" {
		t.Errorf("expired order carries certificate %q", got.CertURL)
	}
}

// An expired authorization presents as expired and its challenges can no
// longer be answered.
func TestExpiredAuthorizationRefusesChallenge(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	ts, _ := newTestServer(t, testServerConfig{storage: storage})
	client := newACMEClient(t, ts)

	order, chal := pendingChallenge(t, client, "expired-authz-device")
	expireAuthorization(t, storage, order.AuthzURLs[0])

	authz, err := client.GetAuthorization(t.Context(), order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}
	if authz.Status != acme.StatusExpired {
		t.Errorf("expired authorization status = %q, want %q", authz.Status, acme.StatusExpired)
	}

	err = submitAttObj(t, client, chal, nullAttObj(t))
	var ae *acme.Error
	if !errors.As(err, &ae) || ae.ProblemType != "urn:ietf:params:acme:error:malformed" {
		t.Errorf("challenge response on expired authorization error = %v, want malformed", err)
	}
}

// An expired authorization is a final state other than valid, so a poll
// durably settles the pending order as invalid per RFC 8555 Section 7.1.6.
func TestExpiredAuthorizationSettlesOrderInvalid(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	ts, _ := newTestServer(t, testServerConfig{storage: storage})
	client := newACMEClient(t, ts)

	order, _ := pendingChallenge(t, client, "expired-authz-order-device")
	expireAuthorization(t, storage, order.AuthzURLs[0])

	got, err := client.GetOrder(t.Context(), order.URI)
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if got.Status != acme.StatusInvalid {
		t.Errorf("order status = %q, want %q", got.Status, acme.StatusInvalid)
	}

	stored, _, err := storage.GetOrder(t.Context(), path.Base(order.URI))
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if stored.Status != nanoca.OrderStatusInvalid {
		t.Errorf("stored order status = %q, want %q", stored.Status, nanoca.OrderStatusInvalid)
	}
}

// deviceInfoRecordingIssuer records how many attested identities each
// issuance received.
type deviceInfoRecordingIssuer struct {
	selfSignedIssuer
	mu     sync.Mutex
	counts []int
}

func (i *deviceInfoRecordingIssuer) IssueCertificate(ctx context.Context, csr *x509.CertificateRequest, infos []*nanoca.DeviceInfo) (*nanoca.Certificate, error) {
	i.mu.Lock()
	i.counts = append(i.counts, len(infos))
	i.mu.Unlock()
	return i.selfSignedIssuer.IssueCertificate(ctx, csr, infos)
}

// An expired authorization no longer vouches for its identity, so an order
// carrying one is no longer backed by all the identities it proved:
// finalize must refuse it rather than issue a certificate that silently
// lacks the expired identifier's SANs.
func TestFinalizeRefusesOrderWithExpiredAuthorization(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	issuer := &deviceInfoRecordingIssuer{}
	ts, _ := newTestServer(t, testServerConfig{storage: storage, issuer: issuer})
	client := newACMEClient(t, ts)

	order, err := client.AuthorizeOrder(t.Context(), []acme.AuthzID{
		{Type: "permanent-identifier", Value: "expired-half-a"},
		{Type: "permanent-identifier", Value: "expired-half-b"},
	})
	if err != nil {
		t.Fatalf("AuthorizeOrder() error = %v", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(t.Context(), authzURL)
		if err != nil {
			t.Fatalf("GetAuthorization() error = %v", err)
		}
		if err := submitAttObj(t, client, authz.Challenges[0], nullAttObj(t)); err != nil {
			t.Fatalf("failed to satisfy challenge: %v", err)
		}
	}

	expireAuthorization(t, storage, order.AuthzURLs[0])

	_, _, err = client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	var ae *acme.Error
	if !errors.As(err, &ae) || ae.ProblemType != "urn:ietf:params:acme:error:unauthorized" {
		t.Errorf("finalize with an expired authorization error = %v, want unauthorized", err)
	}

	issuer.mu.Lock()
	counts := slices.Clone(issuer.counts)
	issuer.mu.Unlock()
	if len(counts) != 0 {
		t.Errorf("identities per issuance = %v, want no issuance", counts)
	}

	got, err := client.GetOrder(t.Context(), order.URI)
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if got.Status != acme.StatusInvalid {
		t.Errorf("order status after refused finalize = %q, want %q", got.Status, acme.StatusInvalid)
	}
}
