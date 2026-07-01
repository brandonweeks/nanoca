package nanoca_test

import (
	"testing"

	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
	"golang.org/x/crypto/acme"
)

func TestCrossAccountAccess(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())

	owner := newACMEClient(t, ts)
	order, err := owner.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "permanent-identifier", Value: "owned-device"}})
	if err != nil {
		t.Fatalf("failed to create order: %v", err)
	}
	authz, err := owner.GetAuthorization(t.Context(), order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("failed to get authorization: %v", err)
	}

	other := newACMEClient(t, ts)

	if _, err := other.GetOrder(t.Context(), order.URI); err == nil {
		t.Error("GetOrder() by other account error = nil, want unauthorized")
	}
	if _, err := other.GetAuthorization(t.Context(), order.AuthzURLs[0]); err == nil {
		t.Error("GetAuthorization() by other account error = nil, want unauthorized")
	}
	if _, err := other.GetChallenge(t.Context(), authz.Challenges[0].URI); err == nil {
		t.Error("GetChallenge() by other account error = nil, want unauthorized")
	}
}

func TestCertificateWrongAccount(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())

	client, order := driveToReady(t, ts)
	_, certURL, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	if err != nil {
		t.Fatalf("failed to issue certificate: %v", err)
	}

	other := newACMEClient(t, ts)
	if _, err := other.FetchCert(t.Context(), certURL, true); err == nil {
		t.Error("FetchCert() by other account error = nil, want unauthorized")
	}
}
