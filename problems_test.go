package nanoca_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/brandonweeks/nanoca"
)

func TestProblemConstructors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		problem    *nanoca.Problem
		wantStatus int
	}{
		{"InternalServerError", nanoca.InternalServerError("boom"), http.StatusInternalServerError},
		{"Malformed", nanoca.Malformed("boom"), http.StatusBadRequest},
		{"BadNonce", nanoca.BadNonce("boom"), http.StatusBadRequest},
		{"BadCSR", nanoca.BadCSR("boom"), http.StatusBadRequest},
		{"BadSignatureAlgorithm", nanoca.BadSignatureAlgorithm("boom", []string{"ES256"}), http.StatusBadRequest},
		{"InvalidContact", nanoca.InvalidContact("boom"), http.StatusBadRequest},
		{"Unauthorized", nanoca.Unauthorized("boom"), http.StatusForbidden},
		{"AccountDoesNotExist", nanoca.AccountDoesNotExist("boom"), http.StatusBadRequest},
		{"MethodNotAllowed", nanoca.MethodNotAllowed("boom"), http.StatusMethodNotAllowed},
		{"UnsupportedMediaTypeProblem", nanoca.UnsupportedMediaTypeProblem("boom"), http.StatusUnsupportedMediaType},
		{"RequestTooLarge", nanoca.RequestTooLarge("boom"), http.StatusRequestEntityTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.problem.Status; got != tt.wantStatus {
				t.Errorf("Status = %d, want %d", got, tt.wantStatus)
			}
			if !strings.HasPrefix(tt.problem.Type, nanoca.ACMEProblemTypePrefix) {
				t.Errorf("Type = %q, want prefix %q", tt.problem.Type, nanoca.ACMEProblemTypePrefix)
			}
			if got := tt.problem.Error(); !strings.Contains(got, "boom") {
				t.Errorf("Error() = %q, want it to contain the detail", got)
			}
		})
	}

	if algs := nanoca.BadSignatureAlgorithm("boom", []string{"ES256"}).Algorithms; len(algs) != 1 || algs[0] != "ES256" {
		t.Errorf("Algorithms = %v, want [ES256]", algs)
	}
}
