package nanoca

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Reservations and the stored attestation blob are storage concerns; they
// must never reach the ACME wire format, and scrubbing them must not mutate
// the stored record's copy.
func TestWriteJSONResponseScrubsStorageState(t *testing.T) {
	t.Parallel()

	ca := &CA{logger: slog.New(slog.DiscardHandler)}
	reservation := func() *Reservation {
		return &Reservation{Token: "token", ReservedAt: time.Now()}
	}
	attestation := []byte("attestation-object")

	order := &Order{ID: "o1", Status: OrderStatusProcessing, Reservation: reservation()}
	challenge := &Challenge{ID: "c1", Status: ChallengeStatusValid, Attestation: attestation, Reservation: reservation()}
	authz := &Authorization{ID: "a1", Challenges: []Challenge{{ID: "c1", Attestation: attestation, Reservation: reservation()}}}

	for name, data := range map[string]any{
		"order":         order,
		"challenge":     challenge,
		"authorization": authz,
	} {
		rec := httptest.NewRecorder()
		ca.writeJSONResponse(t.Context(), rec, http.StatusOK, data, "")
		for _, field := range []string{"reservation", "attestation"} {
			if body := rec.Body.String(); strings.Contains(body, field) {
				t.Errorf("%s response leaks %s state:\n%s", name, field, body)
			}
		}
	}

	if order.Reservation == nil || challenge.Reservation == nil || authz.Challenges[0].Reservation == nil {
		t.Error("scrubbing mutated the caller's records")
	}
	if challenge.Attestation == nil || authz.Challenges[0].Attestation == nil {
		t.Error("scrubbing mutated the caller's attestation")
	}
}
