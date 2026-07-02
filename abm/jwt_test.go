package abm_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca/abm"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}

func cacheFileFor(clientID string) string {
	h := sha256.Sum256([]byte(clientID))
	return filepath.Join(".nanoca_cache", "abm_tokens", hex.EncodeToString(h[:8])+".json")
}

func writeCachedToken(t *testing.T, clientID string, expiry, created, expiresAt time.Time) string {
	t.Helper()
	path := cacheFileFor(clientID)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(".nanoca_cache") })

	cached := fmt.Sprintf(
		`{"token":{"access_token":"tok","token_type":"Bearer","expiry":%q},"created":%q,"expires_at":%q}`,
		expiry.Format(time.RFC3339), created.Format(time.RFC3339), expiresAt.Format(time.RFC3339),
	)
	if err := os.WriteFile(path, []byte(cached), 0o600); err != nil {
		t.Fatalf("failed to write cache file: %v", err)
	}
	return path
}

func newJWTClient(t *testing.T, config *abm.JWTConfig) *http.Client {
	t.Helper()
	client, err := abm.CreateJWTClient(t.Context(), config)
	if err != nil {
		t.Fatalf("CreateJWTClient() error = %v", err)
	}
	return client
}

func expectExchangeFailure(t *testing.T, client *http.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://unused.invalid/", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Error("request error = nil, want token exchange failure")
	}
}

func TestCachedTokenSkipsExchange(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	writeCachedToken(t, "cached-client", future, now, future)

	client := newJWTClient(t, &abm.JWTConfig{ClientID: "cached-client", PrivateKey: newKey(t)})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request with cached token failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestExpiredCachedTokenIsPurged(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	path := writeCachedToken(t, "expired-client", past, past, past)

	client := newJWTClient(t, &abm.JWTConfig{ClientID: "expired-client", PrivateKey: newKey(t)})

	expectExchangeFailure(t, client)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expired cache file was not purged")
	}
}

func TestTokenExchangeSignsJWT(t *testing.T) {
	client := newJWTClient(t, &abm.JWTConfig{
		ClientID:   "exchange-client",
		PrivateKey: newKey(t),
		KeyID:      "key-id",
	})

	expectExchangeFailure(t, client)
}
