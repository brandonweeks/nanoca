package nanoca_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/brandonweeks/nanoca"
	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/acme"
)

type erroringVerifier struct{}

func (erroringVerifier) Format() string { return "failing" }

func (erroringVerifier) Verify(context.Context, nanoca.AttestationStatement, []byte) (*nanoca.DeviceInfo, error) {
	return nil, errors.New("attestation invalid")
}

func TestChallengeVerifierFailure(t *testing.T) {
	t.Parallel()

	ts, _ := newTestServer(t, nullauthorizer.New(), nil, nil, erroringVerifier{})
	client := newACMEClient(t, ts)

	order, chal := pendingChallenge(t, client, "failing-device")

	attObj, err := cbor.Marshal(map[string]any{"fmt": "failing", "attStmt": map[string]any{}})
	if err != nil {
		t.Fatalf("failed to marshal attestation: %v", err)
	}
	if err := submitAttObj(t, client, chal, base64.RawURLEncoding.EncodeToString(attObj)); err == nil {
		t.Error("Accept() error = nil, want verification failure")
	}

	authz, err := client.GetAuthorization(t.Context(), order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("failed to get authorization: %v", err)
	}
	if authz.Status != acme.StatusInvalid {
		t.Errorf("authorization status = %q, want invalid", authz.Status)
	}
}
