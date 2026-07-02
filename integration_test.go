package nanoca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
	"github.com/brandonweeks/nanoca/issuers/inprocess"
	filesigner "github.com/brandonweeks/nanoca/signers/file"
	store "github.com/brandonweeks/nanoca/storage/badger"
	"github.com/brandonweeks/nanoca/verifiers/null"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/acme"
)

type mockIssuanceObserver struct{}

func (m *mockIssuanceObserver) OnIssuance(_ context.Context, _ *nanoca.IssuanceEvent) error {
	return nil
}

func createNullDeviceAttestation() map[string]any {
	return map[string]any{
		"fmt":     "null",
		"attStmt": map[string]any{},
	}
}

func TestDeviceAttestationFlow(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())

	client := &acme.Client{
		DirectoryURL: ts.URL + "/directory",
		HTTPClient:   ts.Client(),
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate account key: %v", err)
	}

	client.Key = accountKey

	account := &acme.Account{
		Contact: []string{"mailto:test@example.com"},
	}

	_, err = client.Register(ctx, account, acme.AcceptTOS)
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	identifiers := []acme.AuthzID{
		{
			Type:  "permanent-identifier",
			Value: "device-android-12345",
		},
	}

	order, err := client.AuthorizeOrder(ctx, identifiers)
	if err != nil {
		t.Fatalf("Failed to create order with single identifier: %v", err)
	}

	authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("Failed to retrieve authorization: %v", err)
	}

	if authz.Status != acme.StatusPending {
		t.Errorf("Authorization status should be pending, got: %s", authz.Status)
	}

	if authz.Identifier.Type != "permanent-identifier" || authz.Identifier.Value != "device-android-12345" {
		t.Errorf("Authorization identifier mismatch: got %+v", authz.Identifier)
	}

	deviceChallenge := authz.Challenges[0]
	if deviceChallenge.Type != "device-attest-01" {
		t.Errorf("Expected device-attest-01 challenge, got: %s", deviceChallenge.Type)
	}
	if deviceChallenge.Status != acme.StatusPending {
		t.Errorf("Challenge status should be pending, got: %s", deviceChallenge.Status)
	}
	if deviceChallenge.Token == "" {
		t.Error("Challenge token should not be empty")
	}

	_, err = client.GetOrder(ctx, order.URI)
	if err != nil {
		t.Fatalf("Failed to retrieve order: %v", err)
	}

	nullAttestation := createNullDeviceAttestation()

	attObjBytes, err := cbor.Marshal(nullAttestation)
	if err != nil {
		t.Fatalf("Failed to marshal attestation object to CBOR: %v", err)
	}

	attObjB64 := base64.RawURLEncoding.EncodeToString(attObjBytes)

	challengeResp := map[string]any{
		"attObj": attObjB64,
	}

	payloadBytes, err := json.Marshal(challengeResp)
	if err != nil {
		t.Fatalf("Failed to marshal challenge response: %v", err)
	}

	deviceChallenge.Payload = json.RawMessage(payloadBytes)

	updatedChallenge, err := client.Accept(ctx, deviceChallenge)
	if err != nil {
		t.Fatalf("Failed to submit device attestation challenge: %v", err)
	}

	deviceChallenge = updatedChallenge

	challenge, err := client.GetChallenge(ctx, deviceChallenge.URI)
	if err != nil {
		t.Fatalf("Failed to get updated challenge: %v", err)
	}

	if challenge.Status == acme.StatusInvalid {
		t.Fatalf("Challenge validation failed")
	}

	_, err = client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("Failed to get updated authorization: %v", err)
	}

	retrievedOrder, err := client.GetOrder(ctx, order.URI)
	if err != nil {
		t.Fatalf("Failed to retrieve order for finalization: %v", err)
	}

	if retrievedOrder.Status == acme.StatusReady || retrievedOrder.Status == acme.StatusPending {
		certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate certificate key: %v", err)
		}

		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "Device Certificate",
				Organization: []string{"Test Organization"},
			},
		}

		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certKey)
		if err != nil {
			t.Fatalf("Failed to create CSR: %v", err)
		}

		cert, _, err := client.CreateOrderCert(ctx, retrievedOrder.FinalizeURL, csrDER, true)
		if err != nil {
			t.Fatalf("Failed to finalize order: %v", err)
		}

		if len(cert) > 0 {
			if _, err := x509.ParseCertificate(cert[0]); err != nil {
				t.Fatalf("Failed to parse certificate: %v", err)
			}

			if len(cert) != 2 {
				t.Fatalf("Expected exactly two certificates (leaf + intermediate, self-signed root omitted), got %d", len(cert))
			}

			intermediateCert, err := x509.ParseCertificate(cert[1])
			if err != nil {
				t.Fatalf("Failed to parse intermediate certificate: %v", err)
			}
			if !intermediateCert.IsCA {
				t.Error("Second certificate in chain should be a CA certificate")
			}
			if intermediateCert.Subject.CommonName != "Test Intermediate CA" {
				t.Errorf("Intermediate common name = %v, want Test Intermediate CA", intermediateCert.Subject.CommonName)
			}
		} else {
			t.Error("No certificate data returned")
		}
	} else {
		t.Logf("Order status is %s, skipping certificate issuance test", retrievedOrder.Status)
	}
}

func setupTestServerWithAttestation(t *testing.T, authorizer nanoca.Authorizer) (*httptest.Server, *nanoca.CA) {
	t.Helper()
	return newTestServer(t, authorizer, nil, nil)
}

func newTestServer(t *testing.T, authorizer nanoca.Authorizer, issuerOverride nanoca.CertificateIssuer, observerOverride nanoca.IssuanceObserver, extraVerifiers ...nanoca.AttestationVerifier) (*httptest.Server, *nanoca.CA) {
	t.Helper()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	signer, err := filesigner.LoadSigner("testing/rootCA.key")
	if err != nil {
		t.Fatalf("Failed to load signer from file: %v", err)
	}

	caCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, signer.Public(), signer)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	intermKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate intermediate key: %v", err)
	}

	intermCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test Intermediate CA",
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	intermCertDER, err := x509.CreateCertificate(rand.Reader, intermCertTemplate, caCert, &intermKey.PublicKey, signer)
	if err != nil {
		t.Fatalf("Failed to create intermediate CA certificate: %v", err)
	}

	intermCert, err := x509.ParseCertificate(intermCertDER)
	if err != nil {
		t.Fatalf("Failed to parse intermediate CA certificate: %v", err)
	}

	storage, err := store.New(store.Options{InMemory: true})
	if err != nil {
		t.Fatalf("Failed to create in-memory storage: %v", err)
	}

	issuer := issuerOverride
	if issuer == nil {
		inproc, err := inprocess.New(intermKey, intermCert, caCert)
		if err != nil {
			t.Fatalf("Failed to create certificate issuer: %v", err)
		}
		issuer = inproc
	}

	observer := observerOverride
	if observer == nil {
		observer = &mockIssuanceObserver{}
	}

	opts := []nanoca.Option{nanoca.WithObserver(observer), nanoca.WithVerifier(null.New())}
	for _, v := range extraVerifiers {
		opts = append(opts, nanoca.WithVerifier(v))
	}

	ca, err := nanoca.New(
		slog.New(slog.DiscardHandler),
		issuer,
		authorizer,
		storage,
		ts.URL,
		opts...,
	)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	ts.Config.Handler = ca.Handler()
	t.Cleanup(func() { ts.Close(); _ = ca.Close() })
	return ts, ca
}
