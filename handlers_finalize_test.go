package nanoca_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/brandonweeks/nanoca"
	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
	"golang.org/x/crypto/acme"
)

type failingIssuer struct{}

func (failingIssuer) IssueCertificate(context.Context, *x509.CertificateRequest, []*nanoca.DeviceInfo) (*nanoca.Certificate, error) {
	return nil, errors.New("issuer unavailable")
}

type failingObserver struct{}

func (failingObserver) OnIssuance(context.Context, *nanoca.IssuanceEvent) error {
	return errors.New("observer failed")
}

func newCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device"}}, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	return der
}

func driveToReady(t *testing.T, ts *httptest.Server) (*acme.Client, *acme.Order) {
	t.Helper()
	client := newACMEClient(t, ts)
	order, chal := pendingChallenge(t, client, "ready-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}
	return client, order
}

func TestFinalizeIssuerError(t *testing.T) {
	t.Parallel()

	ts, _ := newTestServer(t, testServerConfig{issuer: failingIssuer{}})

	client, order := driveToReady(t, ts)
	if _, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true); err == nil {
		t.Error("CreateOrderCert() error = nil, want issuer failure")
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The client only sees "Failed to finalize certificate", so the causing error
// has to reach the server log or the 500 cannot be debugged.
func TestFinalizeIssuerErrorLogged(t *testing.T) {
	t.Parallel()

	var logs syncBuffer
	ts, _ := newTestServer(t, testServerConfig{logger: slog.New(slog.NewTextHandler(&logs, nil)), issuer: failingIssuer{}})

	client, order := driveToReady(t, ts)
	if _, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true); err == nil {
		t.Fatal("CreateOrderCert() error = nil, want issuer failure")
	}

	if !strings.Contains(logs.String(), "issuer unavailable") {
		t.Errorf("finalize failure logs omit the issuer error %q:\n%s", "issuer unavailable", logs.String())
	}
	if got := strings.Count(logs.String(), "level=ERROR"); got != 1 {
		t.Errorf("finalize failure produced %d error records, want 1:\n%s", got, logs.String())
	}
}

func TestFinalizeObserverErrorStillIssues(t *testing.T) {
	t.Parallel()

	ts, _ := newTestServer(t, testServerConfig{observer: failingObserver{}})

	client, order := driveToReady(t, ts)
	cert, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	if err != nil {
		t.Fatalf("CreateOrderCert() error = %v, want success", err)
	}
	if len(cert) == 0 {
		t.Error("CreateOrderCert() returned no certificate")
	}
}

// RFC 8555 Section 7.4 conditions the orderNotReady MUST only on order
// state, so it takes precedence over CSR validation: a client whose CSR is
// also broken must still learn the order isn't ready, not get a terminal
// badCSR for an order that may yet become finalizable.
func TestFinalizeNotReadyBadCSR(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())

	client := newACMEClient(t, ts)
	order, _ := pendingChallenge(t, client, "pending-bad-csr-device")
	_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, []byte("not a csr"), true)

	var ae *acme.Error
	if !errors.As(err, &ae) {
		t.Fatalf("CreateOrderCert() error = %v, want *acme.Error", err)
	}
	if ae.ProblemType != "urn:ietf:params:acme:error:orderNotReady" {
		t.Errorf("problem type = %q, want orderNotReady", ae.ProblemType)
	}
}

// Ownership is judged before the CSR: a foreign account probing another
// account's finalize URL gets unauthorized, not CSR-validation feedback.
func TestFinalizeForeignOrder(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())

	owner := newACMEClient(t, ts)
	order, _ := pendingChallenge(t, owner, "owned-finalize-device")

	other := newACMEClient(t, ts)
	_, _, err := other.CreateOrderCert(t.Context(), order.FinalizeURL, []byte("not a csr"), true)

	var ae *acme.Error
	if !errors.As(err, &ae) {
		t.Fatalf("CreateOrderCert() error = %v, want *acme.Error", err)
	}
	if ae.ProblemType != "urn:ietf:params:acme:error:unauthorized" {
		t.Errorf("problem type = %q, want unauthorized", ae.ProblemType)
	}
}

// RFC 8555 Section 7.4: after badCSR the order SHOULD stay in "ready" so
// the client can submit a new finalize request with an amended CSR.
func TestFinalizeBadCSRLeavesOrderReady(t *testing.T) {
	t.Parallel()

	ts, _ := newTestServer(t, testServerConfig{})

	client, order := driveToReady(t, ts)

	_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, []byte("not a csr"), true)
	var ae *acme.Error
	if !errors.As(err, &ae) {
		t.Fatalf("CreateOrderCert() error = %v, want *acme.Error", err)
	}
	if ae.ProblemType != "urn:ietf:params:acme:error:badCSR" {
		t.Errorf("problem type = %q, want badCSR", ae.ProblemType)
	}

	if _, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true); err != nil {
		t.Fatalf("CreateOrderCert() with amended CSR error = %v, want success", err)
	}
}

// RFC 8555 Section 7.4: finalizing an order that is not ready MUST return
// 403 orderNotReady, which clients treat as retriable; malformed is terminal.
func TestFinalizeNotReady(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())

	client := newACMEClient(t, ts)
	order, _ := pendingChallenge(t, client, "pending-device")
	_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)

	var ae *acme.Error
	if !errors.As(err, &ae) {
		t.Fatalf("CreateOrderCert() error = %v, want *acme.Error", err)
	}
	if ae.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d", ae.StatusCode, http.StatusForbidden)
	}
	if ae.ProblemType != "urn:ietf:params:acme:error:orderNotReady" {
		t.Errorf("problem type = %q, want orderNotReady", ae.ProblemType)
	}
}
