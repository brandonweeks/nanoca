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

// Integration tests for nanoca ACME server
//
// Note: This file contains a single comprehensive end-to-end test that
// exercises the complete ACME flow.

// mockIssuanceObserver is a simple mock issuance observer for testing
type mockIssuanceObserver struct{}

func (m *mockIssuanceObserver) OnIssuance(_ context.Context, _ *nanoca.IssuanceEvent) error {
	return nil
}

// createNullDeviceAttestation creates a null ACME Device Attestation object
// This is useful for testing and development scenarios where no actual device attestation is available
func createNullDeviceAttestation() map[string]any {
	return map[string]any{
		"fmt":     "null",
		"attStmt": map[string]any{},
		// Note: authData is omitted as per ACME Device Attestation specification
		// The key authorization is used as attToBeSigned instead of authData + clientDataHash
	}
}

// TestDeviceAttestationFlow tests the complete ACME flow including device
// attestation challenges end-to-end
func TestDeviceAttestationFlow(t *testing.T) {
	t.Parallel()

	ts, ca := setupTestServerWithAttestation(t)
	defer ts.Close()
	defer ca.Close()

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

	_, err = client.Register(ctx, account, func(tosURL string) bool {
		t.Logf("Terms of Service URL: %s", tosURL)
		return true
	})
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
	t.Logf("Found device-attest-01 challenge: %s (token: %s)", deviceChallenge.URI, deviceChallenge.Token[:8]+"...")

	_, err = client.GetOrder(ctx, order.URI)
	if err != nil {
		t.Fatalf("Failed to retrieve order: %v", err)
	}

	// Create null attestation object as per ACME Device Attestation spec
	nullAttestation := createNullDeviceAttestation()

	// Encode the attestation object as CBOR as per WebAuthn specification
	attObjBytes, err := cbor.Marshal(nullAttestation)
	if err != nil {
		t.Fatalf("Failed to marshal attestation object to CBOR: %v", err)
	}

	// Base64url encode the attestation object
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

	switch challenge.Status {
	case acme.StatusValid:
		t.Log("Challenge validated successfully!")
	case acme.StatusInvalid:
		t.Fatalf("Challenge validation failed")
	}

	updatedAuthz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("Failed to get updated authorization: %v", err)
	}

	t.Logf("Authorization status: %s", updatedAuthz.Status)
	if updatedAuthz.Status == acme.StatusValid {
		t.Log("Authorization is now valid - ready for certificate issuance!")
		// break
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

		cert, certURL, err := client.CreateOrderCert(ctx, retrievedOrder.FinalizeURL, csrDER, true)
		if err != nil {
			t.Fatalf("Failed to finalize order: %v", err)
		}

		if len(cert) > 0 {
			parsedCert, err := x509.ParseCertificate(cert[0])
			if err != nil {
				t.Fatalf("Failed to parse certificate: %v", err)
			}

			t.Logf("Certificate downloaded successfully:")
			t.Logf("  Subject: %s", parsedCert.Subject.String())
			t.Logf("  Serial Number: %s", parsedCert.SerialNumber.String())
			t.Logf("  Valid From: %s", parsedCert.NotBefore.Format(time.RFC3339))
			t.Logf("  Valid Until: %s", parsedCert.NotAfter.Format(time.RFC3339))
			t.Logf("  Certificate URL: %s", certURL)
		} else {
			t.Error("No certificate data returned")
		}
	} else {
		t.Logf("Order status is %s, skipping certificate issuance test", retrievedOrder.Status)
	}
}

// setupTestServerWithAttestation creates a test server with attestation verifiers
func setupTestServerWithAttestation(t *testing.T) (*httptest.Server, *nanoca.CA) {
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

	storage, err := store.New(store.Options{InMemory: true})
	if err != nil {
		t.Fatalf("Failed to create in-memory storage: %v", err)
	}

	ca, err := nanoca.New(
		slog.New(slog.DiscardHandler),
		inprocess.New(caCert, signer),
		nullauthorizer.New(),
		storage,
		ts.URL,
		nanoca.WithObserver(&mockIssuanceObserver{}),
		nanoca.WithVerifier(null.New()),
	)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	ts.Config.Handler = ca.Handler()
	return ts, ca
}
