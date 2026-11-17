package nanoca

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

type yesGate struct{}

func (yesGate) AuthorizeUnattested(context.Context, UnattestedRequest) (bool, error) {
	return true, nil
}

// A stored unattested challenge on an instance without the gate is this
// instance's configuration, like a missing verifier, so finalize stays
// retriable.
func TestExtractUnattestedWithoutGateIsRetriable(t *testing.T) {
	t.Parallel()
	ca := &CA{logger: slog.New(slog.DiscardHandler)}
	_, err := ca.extractDeviceInfoFromChallenge(t.Context(), &Challenge{Status: ChallengeStatusValid, Unattested: true})
	if err == nil {
		t.Fatal("extractDeviceInfoFromChallenge() succeeded without the gate")
	}
	if _, ok := errors.AsType[*Problem](err); ok {
		t.Errorf("error = %v is a problem, which failOrder treats as terminal", err)
	}
}

func TestExtractUnattestedWithGate(t *testing.T) {
	t.Parallel()
	ca := &CA{logger: slog.New(slog.DiscardHandler), unattested: yesGate{}}
	got, err := ca.extractDeviceInfoFromChallenge(t.Context(), &Challenge{Status: ChallengeStatusValid, Unattested: true})
	if err != nil {
		t.Fatalf("extractDeviceInfoFromChallenge() error = %v", err)
	}
	if got == nil || !got.Unattested || got.PublicKey != nil || got.PermanentIdentifier != nil || got.HardwareModule != nil {
		t.Errorf("DeviceInfo = %+v, want only Unattested", got)
	}
}

type claimsUnattestedVerifier struct{}

func (claimsUnattestedVerifier) Format() string { return "claims" }

func (claimsUnattestedVerifier) Verify(context.Context, AttestationStatement, []byte) (*DeviceInfo, error) {
	return &DeviceInfo{Unattested: true}, nil
}

func TestReverifyRejectsUnattestedClaim(t *testing.T) {
	t.Parallel()
	att, err := cbor.Marshal(AttestationObject{Format: "claims", AttStmt: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	ca := &CA{logger: slog.New(slog.DiscardHandler), verifiers: map[string]AttestationVerifier{"claims": claimsUnattestedVerifier{}}}
	_, err = ca.extractDeviceInfoFromChallenge(t.Context(), &Challenge{Status: ChallengeStatusValid, Attestation: att})
	if err == nil {
		t.Fatal("re-verification accepted a verifier claiming an unattested device")
	}
	if _, ok := errors.AsType[*Problem](err); ok {
		t.Errorf("error = %v is a problem; a re-verification failure stays retriable", err)
	}
}
