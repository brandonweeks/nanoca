package nanoca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/acme"
)

type denyAuthorizer struct{ err error }

func (d denyAuthorizer) Authorize(context.Context, *nanoca.DeviceInfo) (bool, error) {
	return false, d.err
}

func newACMEClient(t *testing.T, ts *httptest.Server) *acme.Client {
	t.Helper()
	client := newUnregisteredClient(t, ts)
	if _, err := client.Register(t.Context(), &acme.Account{}, acme.AcceptTOS); err != nil {
		t.Fatalf("failed to register account: %v", err)
	}
	return client
}

func newUnregisteredClient(t *testing.T, ts *httptest.Server) *acme.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return &acme.Client{
		DirectoryURL: ts.URL + "/directory",
		HTTPClient:   ts.Client(),
		Key:          key,
		// The client treats every 5xx as retriable and would loop until the
		// test context is cancelled; fail on the first response instead.
		RetryBackoff: func(int, *http.Request, *http.Response) time.Duration { return -1 },
	}
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

type staticNonce string

func (n staticNonce) Nonce() (string, error) { return string(n), nil }

// signedPostAsGet issues a POST-as-GET (RFC 8555 Section 6.3): an
// empty-payload JWS signed with the account key, carrying the account URL
// as kid. x/crypto/acme has no orders-list call, so the fetch is built by
// hand.
func signedPostAsGet(t *testing.T, ts *httptest.Server, key *ecdsa.PrivateKey, kid, url string) (int, []byte) {
	t.Helper()

	nonce := fetchNonce(t, ts.Client(), ts.URL)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		&jose.SignerOptions{
			NonceSource:  staticNonce(nonce),
			ExtraHeaders: map[jose.HeaderKey]any{"url": url},
		},
	)
	if err != nil {
		t.Fatalf("failed to build signer: %v", err)
	}
	jws, err := signer.Sign([]byte{})
	if err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(jws.FullSerialize()))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Content-Type", joseContentType)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	return resp.StatusCode, body
}

// RFC 8555 Section 7.1.2 requires the account object to carry the orders
// URL, and clients may refuse an account without one before ever sending
// newOrder. Both account responses must name a resolvable order list for
// enrollment to complete.
func TestAccountOrdersURLResolvable(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	client := &acme.Client{
		DirectoryURL: ts.URL + "/directory",
		HTTPClient:   ts.Client(),
		Key:          key,
		RetryBackoff: func(int, *http.Request, *http.Response) time.Duration { return -1 },
	}

	acct, err := client.Register(t.Context(), &acme.Account{}, acme.AcceptTOS)
	if err != nil {
		t.Fatalf("failed to register account: %v", err)
	}
	if acct.OrdersURL == "" {
		t.Fatal("new-account response carries no orders URL")
	}

	existing, err := client.GetReg(t.Context(), "")
	if err != nil {
		t.Fatalf("GetReg() error = %v", err)
	}
	if existing.OrdersURL != acct.OrdersURL {
		t.Errorf("existing-account orders URL = %q, want %q", existing.OrdersURL, acct.OrdersURL)
	}

	fetchOrders := func() []string {
		t.Helper()
		status, body := signedPostAsGet(t, ts, key, acct.URI, acct.OrdersURL)
		if status != http.StatusOK {
			t.Fatalf("orders fetch status = %d, body: %s", status, body)
		}
		var list struct {
			Orders []string `json:"orders"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatalf("failed to decode orders list: %v", err)
		}
		return list.Orders
	}

	if orders := fetchOrders(); len(orders) != 0 {
		t.Errorf("orders before any order = %v, want empty", orders)
	}

	order, chal := pendingChallenge(t, client, "orders-list-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}
	if _, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true); err != nil {
		t.Fatalf("CreateOrderCert() error = %v", err)
	}

	if orders := fetchOrders(); !slices.Contains(orders, order.URI) {
		t.Errorf("orders list = %v, want to contain %q", orders, order.URI)
	}
}

func TestOrdersListBelongsToAnotherAccount(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())

	ownerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	owner := &acme.Client{DirectoryURL: ts.URL + "/directory", HTTPClient: ts.Client(), Key: ownerKey}
	acct, err := owner.Register(t.Context(), &acme.Account{}, acme.AcceptTOS)
	if err != nil {
		t.Fatalf("failed to register account: %v", err)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	other := &acme.Client{DirectoryURL: ts.URL + "/directory", HTTPClient: ts.Client(), Key: otherKey}
	otherAcct, err := other.Register(t.Context(), &acme.Account{}, acme.AcceptTOS)
	if err != nil {
		t.Fatalf("failed to register account: %v", err)
	}

	if status, _ := signedPostAsGet(t, ts, otherKey, otherAcct.URI, acct.OrdersURL); status != http.StatusForbidden {
		t.Errorf("cross-account orders fetch status = %d, want %d", status, http.StatusForbidden)
	}

	// Only the order list is served under the account URL.
	if status, _ := signedPostAsGet(t, ts, ownerKey, acct.URI, acct.URI); status != http.StatusBadRequest {
		t.Errorf("account URL fetch status = %d, want %d", status, http.StatusBadRequest)
	}
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

// Re-POSTing an already-validated challenge is a client-state condition, not
// a backend failure: a 5xx tells the client to retry an operation that can
// never succeed (see the RetryBackoff comment above).
func TestChallengeDuplicateSubmission(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())
	client := newACMEClient(t, ts)

	_, chal := pendingChallenge(t, client, "duplicate-device")
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}

	err := submitAttObj(t, client, chal, nullAttObj(t))
	var ae *acme.Error
	if errors.As(err, &ae) && ae.StatusCode >= http.StatusInternalServerError {
		t.Errorf("duplicate challenge POST status = %d, want non-5xx", ae.StatusCode)
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

// createOrder builds challenges only for permanent-identifier and
// hardware-module identifiers, so any other type yields an authorization
// with zero challenges. Over an empty challenge list every recompute reads
// all-valid, so such an authorization must never settle valid — nothing was
// ever validated — and its order must not be promoted toward issuance.
func TestZeroChallengeAuthorizationNotSettledValid(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())
	client := newACMEClient(t, ts)

	order, err := client.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "dns", Value: "device.example"}})
	if err != nil {
		// Rejecting the identifier at new-order is also correct.
		return
	}

	authz, err := client.GetAuthorization(t.Context(), order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}
	if authz.Status == acme.StatusValid {
		t.Errorf("authorization with no challenges polled as %q, want never valid", authz.Status)
	}

	polled, err := client.GetOrder(t.Context(), order.URI)
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if polled.Status == acme.StatusReady || polled.Status == acme.StatusValid {
		t.Errorf("order status = %q, want not promoted without any validation", polled.Status)
	}
}
