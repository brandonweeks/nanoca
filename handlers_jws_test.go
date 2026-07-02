package nanoca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"testing"

	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
	"github.com/go-jose/go-jose/v4"
)

func encodeJWS(t *testing.T, protected map[string]any) string {
	t.Helper()

	protBytes, err := json.Marshal(protected)
	if err != nil {
		t.Fatalf("failed to marshal protected header: %v", err)
	}
	body, err := json.Marshal(map[string]string{
		"protected": base64.RawURLEncoding.EncodeToString(protBytes),
		"payload":   "e30", // {}
		"signature": "AAAA",
	})
	if err != nil {
		t.Fatalf("failed to marshal JWS: %v", err)
	}
	return string(body)
}

func craftedJWS(t *testing.T, extra map[string]any) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	jwkJSON, err := (&jose.JSONWebKey{Key: &key.PublicKey, Algorithm: "ES256"}).MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal JWK: %v", err)
	}

	protected := map[string]any{"alg": "ES256", "jwk": json.RawMessage(jwkJSON)}
	maps.Copy(protected, extra)
	return encodeJWS(t, protected)
}

func craftedJWSKid(t *testing.T, kid string) string {
	t.Helper()

	return encodeJWS(t, map[string]any{"alg": "ES256", "kid": kid})
}

func fetchNonce(t *testing.T, client *http.Client, ts string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodHead, ts+"/new-nonce", nil)
	if err != nil {
		t.Fatalf("failed to build nonce request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("nonce request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		t.Fatal("no Replay-Nonce header")
	}
	return nonce
}

func TestJWSValidationErrors(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())
	client := ts.Client()
	url := ts.URL + "/new-account"

	const (
		malformed = "urn:ietf:params:acme:error:malformed"
		badNonce  = "urn:ietf:params:acme:error:badNonce"
	)

	tests := []struct {
		name     string
		extra    map[string]any
		wantType string
	}{
		{"missing nonce", map[string]any{"url": url}, malformed},
		{"missing url", map[string]any{"nonce": "abc"}, malformed},
		{"url mismatch", map[string]any{"nonce": "abc", "url": "https://elsewhere.example/new-account"}, malformed},
		{"unknown nonce", map[string]any{"nonce": "never-issued", "url": url}, badNonce},
		{"jwk and kid", map[string]any{"nonce": "abc", "url": url, "kid": "https://x/account/y"}, malformed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			status, gotType := doRequest(t, client, http.MethodPost, url, joseContentType, craftedJWS(t, tt.extra))
			if status != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
			}
			if gotType != tt.wantType {
				t.Errorf("problem type = %q, want %q", gotType, tt.wantType)
			}
		})
	}

	t.Run("bad signature", func(t *testing.T) {
		body := craftedJWS(t, map[string]any{"nonce": fetchNonce(t, client, ts.URL), "url": url})
		if status, gotType := doRequest(t, client, http.MethodPost, url, joseContentType, body); status != http.StatusBadRequest || gotType != malformed {
			t.Errorf("status/type = %d/%q, want 400/%s", status, gotType, malformed)
		}
	})
}

func TestJWSKidErrors(t *testing.T) {
	t.Parallel()

	ts, _ := setupTestServerWithAttestation(t, nullauthorizer.New())
	client := ts.Client()
	url := ts.URL + "/new-order"

	tests := []struct {
		name string
		kid  string
	}{
		{"malformed kid", "not-an-account-url"},
		{"unknown account", ts.URL + "/account/does-not-exist"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if status, _ := doRequest(t, client, http.MethodPost, url, joseContentType, craftedJWSKid(t, tt.kid)); status != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
			}
		})
	}
}
