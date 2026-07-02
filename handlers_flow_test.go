package nanoca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/brandonweeks/nanoca"
	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/acme"
)

type denyAuthorizer struct{ err error }

func (d denyAuthorizer) Authorize(context.Context, *nanoca.DeviceInfo) (bool, error) {
	return false, d.err
}

func newACMEClient(t *testing.T, ts *httptest.Server) *acme.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	client := &acme.Client{DirectoryURL: ts.URL + "/directory", HTTPClient: ts.Client(), Key: key}
	if _, err := client.Register(t.Context(), &acme.Account{}, acme.AcceptTOS); err != nil {
		t.Fatalf("failed to register account: %v", err)
	}
	return client
}

func pendingChallenge(t *testing.T, client *acme.Client, value string) (*acme.Order, *acme.Challenge) {
	t.Helper()
	order, err := client.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "permanent-identifier", Value: value}})
	if err != nil {
		t.Fatalf("failed to create order: %v", err)
	}
	authz, err := client.GetAuthorization(t.Context(), order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("failed to get authorization: %v", err)
	}
	return order, authz.Challenges[0]
}

func submitAttObj(t *testing.T, client *acme.Client, chal *acme.Challenge, attObjB64 string) error {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"attObj": attObjB64})
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	chal.Payload = payload
	_, err = client.Accept(t.Context(), chal)
	return err
}

func nullAttObj(t *testing.T) string {
	t.Helper()
	b, err := cbor.Marshal(createNullDeviceAttestation())
	if err != nil {
		t.Fatalf("failed to marshal attestation: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestIssuanceExtractsDeviceInfo(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())
	client := newACMEClient(t, ts)

	order, chal := pendingChallenge(t, client, "deviceinfo-device")
	att, err := cbor.Marshal(map[string]any{"fmt": "null", "attStmt": map[string]any{"fmt": "null"}})
	if err != nil {
		t.Fatalf("failed to marshal attestation: %v", err)
	}
	if err := submitAttObj(t, client, chal, base64.RawURLEncoding.EncodeToString(att)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	if _, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true); err != nil {
		t.Fatalf("CreateOrderCert() error = %v", err)
	}
}

func TestMalformedAttestations(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())
	client := newACMEClient(t, ts)

	cborB64 := func(m map[string]any) string {
		b, err := cbor.Marshal(m)
		if err != nil {
			t.Fatalf("cbor marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}

	tests := []struct {
		name   string
		attObj string
	}{
		{"empty attObj", ""},
		{"invalid base64", "!!! not base64 !!!"},
		{"not cbor", base64.RawURLEncoding.EncodeToString([]byte("plain text, not cbor"))},
		{"missing fmt", cborB64(map[string]any{"fmt": "", "attStmt": map[string]any{}})},
		{"unknown fmt", cborB64(map[string]any{"fmt": "bogus", "attStmt": map[string]any{}})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, chal := pendingChallenge(t, client, "dev-"+tt.name)
			if err := submitAttObj(t, client, chal, tt.attObj); err == nil {
				t.Error("Accept() error = nil, want error")
			}
		})
	}
}

func TestDeviceNotAuthorized(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, denyAuthorizer{})
	client := newACMEClient(t, ts)

	order, chal := pendingChallenge(t, client, "denied-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err == nil {
		t.Error("Accept() error = nil, want denial")
	}

	authz, err := client.GetAuthorization(t.Context(), order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("failed to get authorization: %v", err)
	}
	if authz.Status != acme.StatusInvalid {
		t.Errorf("authorization status = %q, want invalid", authz.Status)
	}
}

func TestDuplicateRegistrationReturnsExisting(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	newClient := func() *acme.Client {
		return &acme.Client{DirectoryURL: ts.URL + "/directory", HTTPClient: ts.Client(), Key: key}
	}

	if _, err := newClient().Register(t.Context(), &acme.Account{}, acme.AcceptTOS); err != nil {
		t.Fatalf("first register failed: %v", err)
	}
	// x/crypto/acme returns ErrAccountAlreadyExists on a 200 from newAccount;
	// a nil error means the server minted a duplicate account (201).
	if _, err := newClient().Register(t.Context(), &acme.Account{}, acme.AcceptTOS); !errors.Is(err, acme.ErrAccountAlreadyExists) {
		t.Fatalf("second register error = %v, want ErrAccountAlreadyExists", err)
	}
}

func TestNotFoundLookups(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())
	client := newACMEClient(t, ts)

	tests := []struct {
		name string
		url  string
	}{
		{"order", ts.URL + "/order/does-not-exist"},
		{"authz", ts.URL + "/authz/does-not-exist"},
		{"challenge", ts.URL + "/challenge/does-not-exist"},
		{"certificate", ts.URL + "/certificate/does-not-exist"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := client.GetAuthorization(t.Context(), tt.url); err == nil {
				t.Error("GetAuthorization() error = nil, want error")
			}
		})
	}
}

func TestFinalizeBadCSR(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())
	client := newACMEClient(t, ts)

	order, chal := pendingChallenge(t, client, "finalize-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to accept challenge: %v", err)
	}

	if _, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, []byte("not a valid csr"), true); err == nil {
		t.Error("CreateOrderCert() error = nil, want error")
	}
}

func TestOrderBelongsToAnotherAccount(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())

	owner := newACMEClient(t, ts)
	order, err := owner.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "permanent-identifier", Value: "owned"}})
	if err != nil {
		t.Fatalf("failed to create order: %v", err)
	}

	other := newACMEClient(t, ts)
	if _, err := other.GetOrder(t.Context(), order.URI); err == nil {
		t.Error("GetOrder() by other account error = nil, want error")
	}
}
