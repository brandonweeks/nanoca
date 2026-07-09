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

// Reservations, the stored attestation blob, and the stored ID fields are
// storage concerns; they must never reach the ACME wire format, the URLs
// composed from them must, and presenting must not mutate the stored
// record's copy.
func TestWriteJSONResponseScrubsStorageState(t *testing.T) {
	t.Parallel()

	ca := &CA{logger: slog.New(slog.DiscardHandler)}
	reservation := func() *Reservation {
		return &Reservation{Token: "token", ReservedAt: time.Now()}
	}
	attestation := []byte("attestation-object")

	order := &Order{ID: "o1", Status: OrderStatusProcessing, AuthorizationIDs: []string{"z1"}, CertificateID: "cert1", Reservation: reservation()}
	challenge := &Challenge{ID: "c1", Status: ChallengeStatusValid, Attestation: attestation, Reservation: reservation()}
	authz := &Authorization{ID: "a1", ChallengeIDs: []string{"c1"}, Challenges: []Challenge{{ID: "c1", Attestation: attestation, Reservation: reservation()}}}

	for name, tc := range map[string]struct {
		data     any
		composed []string
	}{
		"order":         {order, []string{`"/authz/z1"`, `"/order/o1/finalize"`, `"/certificate/cert1"`}},
		"challenge":     {challenge, []string{`"/challenge/c1"`}},
		"authorization": {authz, []string{`"/challenge/c1"`}},
	} {
		rec := httptest.NewRecorder()
		ca.writeJSONResponse(t.Context(), rec, http.StatusOK, tc.data, "")
		body := rec.Body.String()
		for _, field := range []string{"reservation", "attestation", "challengeIds", "authorizationIds", "certificateId"} {
			if strings.Contains(body, field) {
				t.Errorf("%s response leaks %s state:\n%s", name, field, body)
			}
		}
		for _, url := range tc.composed {
			if !strings.Contains(body, url) {
				t.Errorf("%s response lacks composed URL %s:\n%s", name, url, body)
			}
		}
	}

	if order.Reservation == nil || challenge.Reservation == nil || authz.Challenges[0].Reservation == nil {
		t.Error("presenting mutated the caller's records")
	}
	if challenge.Attestation == nil || authz.Challenges[0].Attestation == nil {
		t.Error("presenting mutated the caller's attestation")
	}
	if order.AuthorizationIDs == nil || order.CertificateID == "" {
		t.Error("presenting mutated the caller's ID fields")
	}
}
