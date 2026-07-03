package nanoca

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The stored attestation object is a storage concern; it must never reach
// the ACME wire format, and scrubbing it must not mutate the stored
// record's copy.
func TestWriteJSONResponseScrubsStorageState(t *testing.T) {
	t.Parallel()

	ca := &CA{logger: slog.New(slog.DiscardHandler)}
	attestation := map[string]any{"fmt": "apple", "x5c": "leaf"}

	challenge := &Challenge{ID: "c1", Status: ChallengeStatusValid, Attestation: attestation}
	authz := &Authorization{ID: "a1", Challenges: []Challenge{{ID: "c1", Attestation: attestation}}}

	for name, data := range map[string]any{
		"challenge":     challenge,
		"authorization": authz,
	} {
		rec := httptest.NewRecorder()
		ca.writeJSONResponse(t.Context(), rec, http.StatusOK, data, "")
		if body := rec.Body.String(); strings.Contains(body, "attestation") {
			t.Errorf("%s response leaks attestation state:\n%s", name, body)
		}
	}

	if challenge.Attestation == nil || authz.Challenges[0].Attestation == nil {
		t.Error("scrubbing mutated the caller's records")
	}
}
