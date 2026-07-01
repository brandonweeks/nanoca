package nanoca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/brandonweeks/nanoca"
	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
	"golang.org/x/crypto/acme"
)

type failingIssuer struct{}

func (failingIssuer) IssueCertificate(*x509.CertificateRequest, []*nanoca.DeviceInfo) (*nanoca.Certificate, error) {
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

	ts, _ := newTestServer(t, nullauthorizer.New(), failingIssuer{}, nil)

	client, order := driveToReady(t, ts)
	if _, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true); err == nil {
		t.Error("CreateOrderCert() error = nil, want issuer failure")
	}
}

func TestFinalizeObserverErrorStillIssues(t *testing.T) {
	t.Parallel()

	ts, _ := newTestServer(t, nullauthorizer.New(), nil, failingObserver{})

	client, order := driveToReady(t, ts)
	cert, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	if err != nil {
		t.Fatalf("CreateOrderCert() error = %v, want success", err)
	}
	if len(cert) == 0 {
		t.Error("CreateOrderCert() returned no certificate")
	}
}

func TestFinalizeNotReady(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())

	client := newACMEClient(t, ts)
	order, _ := pendingChallenge(t, client, "pending-device")
	if _, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true); err == nil {
		t.Error("CreateOrderCert() error = nil, want not-ready failure")
	}
}
