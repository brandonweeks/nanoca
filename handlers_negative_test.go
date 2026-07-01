package nanoca_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
)

const joseContentType = "application/jose+json"

func doRequest(t *testing.T, client *http.Client, method, url, contentType, body string) (int, string) {
	t.Helper()

	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, url, r)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var prob struct {
		Type string `json:"type"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&prob)
	return resp.StatusCode, prob.Type
}

func TestMethodNotAllowed(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())
	client := ts.Client()

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"POST directory", http.MethodPost, "/directory", http.StatusMethodNotAllowed},
		{"POST new-nonce", http.MethodPost, "/new-nonce", http.StatusMethodNotAllowed},
		{"GET new-account", http.MethodGet, "/new-account", http.StatusMethodNotAllowed},
		{"GET new-order", http.MethodGet, "/new-order", http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if status, _ := doRequest(t, client, tt.method, ts.URL+tt.path, "", ""); status != tt.wantStatus {
				t.Errorf("status = %d, want %d", status, tt.wantStatus)
			}
		})
	}
}

func TestVerifyPOSTErrors(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())
	client := ts.Client()
	url := ts.URL + "/new-order"

	tests := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
	}{
		{"wrong content type", "text/plain", "{}", http.StatusUnsupportedMediaType},
		{"empty body", joseContentType, "", http.StatusBadRequest},
		{"body too large", joseContentType, strings.Repeat("a", (1<<20)+1), http.StatusRequestEntityTooLarge},
		{"not JSON", joseContentType, "not-json", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if status, _ := doRequest(t, client, http.MethodPost, url, tt.contentType, tt.body); status != tt.wantStatus {
				t.Errorf("status = %d, want %d", status, tt.wantStatus)
			}
		})
	}
}

func TestParseJWSErrors(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())
	client := ts.Client()
	url := ts.URL + "/new-account"

	const (
		malformed = "urn:ietf:params:acme:error:malformed"
		badAlg    = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	)
	b64False := "eyJiNjQiOmZhbHNlLCJhbGciOiJFUzI1NiJ9" // {"b64":false,"alg":"ES256"}
	algNone := "eyJhbGciOiJub25lIn0"                   // {"alg":"none"}
	algHS256 := "eyJhbGciOiJIUzI1NiJ9"                 // {"alg":"HS256"}

	tests := []struct {
		name     string
		body     string
		wantType string
	}{
		{"unprotected header", `{"header":{"foo":"bar"},"protected":"e30","payload":"e30","signature":"x"}`, malformed},
		{"signatures member", `{"signatures":[{}],"protected":"e30","payload":"e30","signature":"x"}`, malformed},
		{"detached payload", `{"protected":"e30","signature":"x"}`, malformed},
		{"unencoded payload", `{"protected":"` + b64False + `","payload":"e30","signature":"x"}`, malformed},
		{"alg none", `{"protected":"` + algNone + `","payload":"e30","signature":"x"}`, badAlg},
		{"mac alg", `{"protected":"` + algHS256 + `","payload":"e30","signature":"x"}`, badAlg},
		{"mac alg by prefix", `{"protected":"eyJhbGciOiJIUzk5OSJ9","payload":"e30","signature":"x"}`, badAlg}, // {"alg":"HS999"}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			status, gotType := doRequest(t, client, http.MethodPost, url, joseContentType, tt.body)
			if status != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
			}
			if gotType != tt.wantType {
				t.Errorf("problem type = %q, want %q", gotType, tt.wantType)
			}
		})
	}
}
