package nanoca

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// orderWriteRecorder records whether any order write reached the backend;
// the embedded nil Storage panics on any other call.
type orderWriteRecorder struct {
	Storage
	wrote bool
}

func (s *orderWriteRecorder) GetOrder(_ context.Context, id string) (*Order, Revision, error) {
	return &Order{ID: id, Status: OrderStatusPending}, "1", nil
}

func (s *orderWriteRecorder) PutOrder(context.Context, *Order, Revision) error {
	s.wrote = true
	return nil
}

// Over an empty authorization list every recompute reads all-valid, so an
// order that somehow has none must never be promoted; nothing was ever
// validated.
func TestUpdateOrderStatusNoAuthorizations(t *testing.T) {
	t.Parallel()

	rec := &orderWriteRecorder{}
	ca := &CA{logger: slog.New(slog.DiscardHandler), storage: newStorageMachine(rec)}

	ca.updateOrderStatus(t.Context(), &Order{ID: "o1", Status: OrderStatusPending})
	if rec.wrote {
		t.Error("updateOrderStatus promoted an order with no authorizations")
	}
}

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
	authz := &Authorization{ID: "a1", ChallengeIDs: []string{"c1"}, Challenges: []Challenge{{ID: "c1", Attestation: attestation, Reservation: reservation()}}}

	for name, data := range map[string]any{
		"order":         order,
		"challenge":     challenge,
		"authorization": authz,
	} {
		rec := httptest.NewRecorder()
		ca.writeJSONResponse(t.Context(), rec, http.StatusOK, data, "")
		for _, field := range []string{"reservation", "attestation", "challengeIds"} {
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
