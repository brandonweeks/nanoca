package nanoca_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/brandonweeks/nanoca"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/acme"
)

type erroringVerifier struct{}

func (erroringVerifier) Format() string { return "failing" }

func (erroringVerifier) Verify(context.Context, nanoca.AttestationStatement, []byte) (*nanoca.DeviceInfo, error) {
	return nil, errors.New("attestation invalid")
}

type nilDeviceInfoVerifier struct{}

func (nilDeviceInfoVerifier) Format() string { return "nildev" }

func (nilDeviceInfoVerifier) Verify(context.Context, nanoca.AttestationStatement, []byte) (*nanoca.DeviceInfo, error) {
	return nil, nil
}

// The AttestationVerifier contract does not promise a non-nil DeviceInfo. An
// order whose only identity source is a verifier that yields none can never
// finalize — re-verification deterministically re-yields nothing — so the
// failure must surface as a terminal problem: a 5xx tells the client to
// retry forever (see the RetryBackoff comment in handlers_flow_test.go).
// Refusing the identity-less validation at challenge time is also correct.
func TestFinalizeNilDeviceInfoTerminal(t *testing.T) {
	t.Parallel()

	ts, _ := newTestServer(t, testServerConfig{verifiers: []nanoca.AttestationVerifier{nilDeviceInfoVerifier{}}})
	client := newACMEClient(t, ts)

	order, chal := pendingChallenge(t, client, "nil-identity-device")
	if err := submitAttObj(t, client, chal, attObjFor(t, "nildev")); err != nil {
		return
	}

	_, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	var ae *acme.Error
	if !errors.As(err, &ae) {
		t.Fatalf("CreateOrderCert() error = %v, want *acme.Error", err)
	}
	if ae.StatusCode >= http.StatusInternalServerError {
		t.Errorf("finalize with no attested identity status = %d, want terminal non-5xx", ae.StatusCode)
	}
}

// A verifier that returns no identity leaves finalize nothing to build the
// certificate's SANs from, so the challenge must fail rather than settle
// valid and wedge the order.
func TestChallengeNilDeviceInfoRejected(t *testing.T) {
	t.Parallel()

	ts, _ := newTestServer(t, testServerConfig{verifiers: []nanoca.AttestationVerifier{nilDeviceInfoVerifier{}}})
	client := newACMEClient(t, ts)

	_, chal := pendingChallenge(t, client, "nil-identity-rejected-device")

	err := submitAttObj(t, client, chal, attObjFor(t, "nildev"))
	if err == nil {
		t.Fatal("Accept() error = nil, want rejection of identity-less attestation")
	}

	var ae *acme.Error
	if errors.As(err, &ae) && ae.StatusCode >= http.StatusInternalServerError {
		t.Errorf("challenge POST status = %d, want non-5xx rejection", ae.StatusCode)
	}
}

type captureVerifier struct {
	mu    sync.Mutex
	stmts []nanoca.AttestationStatement
}

func (v *captureVerifier) Format() string { return "capture" }

func (v *captureVerifier) Verify(_ context.Context, stmt nanoca.AttestationStatement, _ []byte) (*nanoca.DeviceInfo, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.stmts = append(v.stmts, stmt)
	return &nanoca.DeviceInfo{
		PermanentIdentifier: &nanoca.PermanentIdentifier{Identifier: "captured-device"},
	}, nil
}

// Finalize re-verifies the stored statement, so the verifier must receive
// what it verified at challenge time. The storage round-trip currently
// rewrites []byte values (an apple x5c chain) into base64 strings and the
// handler injects a "fmt" entry — either breaks a verifier that checks its
// input strictly, as verifiers/apple does.
func TestFinalizeReverifiesOriginalStatement(t *testing.T) {
	t.Parallel()

	verifier := &captureVerifier{}
	ts, _ := newTestServer(t, testServerConfig{verifiers: []nanoca.AttestationVerifier{verifier}})
	client := newACMEClient(t, ts)

	order, chal := pendingChallenge(t, client, "capture-device")
	attObj, err := cbor.Marshal(map[string]any{
		"fmt":     "capture",
		"attStmt": map[string]any{"x5c": []any{[]byte("leaf certificate der")}},
	})
	if err != nil {
		t.Fatalf("failed to marshal attestation: %v", err)
	}
	if err := submitAttObj(t, client, chal, base64.RawURLEncoding.EncodeToString(attObj)); err != nil {
		t.Fatalf("failed to satisfy challenge: %v", err)
	}
	if _, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true); err != nil {
		t.Fatalf("CreateOrderCert() error = %v", err)
	}

	verifier.mu.Lock()
	stmts := verifier.stmts
	verifier.mu.Unlock()
	if len(stmts) != 2 {
		t.Fatalf("Verify calls = %d, want 2 (challenge, finalize)", len(stmts))
	}
	x5c, ok := stmts[0].AttStmt["x5c"].([]any)
	if !ok || len(x5c) != 1 {
		t.Fatalf("challenge-time x5c = %#v, want one-element []any", stmts[0].AttStmt["x5c"])
	}
	if _, ok := x5c[0].([]byte); !ok {
		t.Fatalf("challenge-time x5c[0] type = %T, want []byte", x5c[0])
	}

	finalize := stmts[1].AttStmt
	if _, ok := finalize["fmt"]; ok {
		t.Error(`finalize-time attStmt contains an injected "fmt" key`)
	}
	x5c, ok = finalize["x5c"].([]any)
	if !ok || len(x5c) != 1 {
		t.Fatalf("finalize-time x5c = %#v, want one-element []any", finalize["x5c"])
	}
	if _, ok := x5c[0].([]byte); !ok {
		t.Errorf("finalize-time x5c[0] type = %T, want []byte", x5c[0])
	}
}

func TestChallengeVerifierFailure(t *testing.T) {
	t.Parallel()

	ts, _ := newTestServer(t, testServerConfig{verifiers: []nanoca.AttestationVerifier{erroringVerifier{}}})
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
