package nanoca_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
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

type nilDeviceInfoVerifier struct{}

func (nilDeviceInfoVerifier) Format() string { return "nildev" }

func (nilDeviceInfoVerifier) Verify(context.Context, nanoca.AttestationStatement, []byte) (*nanoca.DeviceInfo, error) {
	return nil, nil
}

// A verifier that returns no identity leaves finalize nothing to build the
// certificate's SANs from, so the challenge must fail rather than settle
// valid and wedge the order.
func TestChallengeNilDeviceInfoRejected(t *testing.T) {
	t.Parallel()

	ts, _ := newTestServer(t, nullauthorizer.New(), nil, nil, nilDeviceInfoVerifier{})
	client := newACMEClient(t, ts)

	_, chal := pendingChallenge(t, client, "nil-identity-device")

	attObj, err := cbor.Marshal(map[string]any{"fmt": "nildev", "attStmt": map[string]any{}})
	if err != nil {
		t.Fatalf("failed to marshal attestation: %v", err)
	}
	err = submitAttObj(t, client, chal, base64.RawURLEncoding.EncodeToString(attObj))
	if err == nil {
		t.Fatal("Accept() error = nil, want rejection of identity-less attestation")
	}

	var ae *acme.Error
	if errors.As(err, &ae) && ae.StatusCode >= http.StatusInternalServerError {
		t.Errorf("challenge POST status = %d, want non-5xx rejection", ae.StatusCode)
	}
}
