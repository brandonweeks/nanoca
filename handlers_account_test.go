package nanoca_test

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"

	"github.com/brandonweeks/nanoca"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/acme"
)

// RFC 8555 Section 7.3.6: a request signed by a deactivated account gets
// unauthorized. nanoca has no deactivation endpoint, so the status is
// changed in storage the way an operator would.
func TestDeactivatedAccountUnauthorized(t *testing.T) {
	t.Parallel()

	storage := newTestStorage(t)
	ts, _ := newTestServer(t, testServerConfig{storage: storage})
	client := newACMEClient(t, ts)

	thumbprint, err := (&jose.JSONWebKey{Key: client.Key.Public()}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("Thumbprint() error = %v", err)
	}
	account, rev, err := storage.GetAccountByKey(t.Context(), base64.RawURLEncoding.EncodeToString(thumbprint))
	if err != nil {
		t.Fatalf("GetAccountByKey() error = %v", err)
	}
	account.Status = nanoca.AccountStatusDeactivated
	if err := storage.PutAccount(t.Context(), account, rev); err != nil {
		t.Fatalf("PutAccount() error = %v", err)
	}

	_, err = client.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "permanent-identifier", Value: testDeviceSerial}})
	var ae *acme.Error
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusForbidden || ae.ProblemType != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("AuthorizeOrder() by deactivated account error = %v, want 403 unauthorized", err)
	}
}

// RFC 8555 Section 6.4: the JWS url is checked against the URL the CA
// publishes, so the Host header plays no part.
func TestRequestURLIgnoresHostHeader(t *testing.T) {
	t.Parallel()

	ts, _ := newTestServer(t, testServerConfig{})
	client := newUnregisteredClient(t, ts)
	acct, err := client.Register(t.Context(), &acme.Account{}, acme.AcceptTOS)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	status, body := signedPostAsGetWithHost(t, ts, client.Key.(*ecdsa.PrivateKey), acct.URI, acct.URI+"/orders", "elsewhere.example")
	if status != http.StatusOK {
		t.Fatalf("orders fetch with foreign Host header status = %d, want 200: %s", status, body)
	}
}
