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

func TestCachedTokenSkipsExchange(t *testing.T) {
	path := cacheFileFor("cached-client")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(".nanoca_cache") })

	future := time.Now().Add(time.Hour)
	cached := fmt.Sprintf(
		`{"token":{"access_token":"tok","token_type":"Bearer","expiry":%q},"created":%q,"expires_at":%q}`,
		future.Format(time.RFC3339), time.Now().Format(time.RFC3339), future.Format(time.RFC3339),
	)
	if err := os.WriteFile(path, []byte(cached), 0o600); err != nil {
		t.Fatalf("failed to write cache file: %v", err)
	}

	client, err := abm.CreateJWTClient(t.Context(), &abm.JWTConfig{ClientID: "cached-client", PrivateKey: newKey(t)})
	if err != nil {
		t.Fatalf("CreateJWTClient() error = %v", err)
	}

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
	path := cacheFileFor("expired-client")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(".nanoca_cache") })

	past := time.Now().Add(-time.Hour)
	cached := fmt.Sprintf(
		`{"token":{"access_token":"tok","token_type":"Bearer","expiry":%q},"created":%q,"expires_at":%q}`,
		past.Format(time.RFC3339), past.Format(time.RFC3339), past.Format(time.RFC3339),
	)
	if err := os.WriteFile(path, []byte(cached), 0o600); err != nil {
		t.Fatalf("failed to write cache file: %v", err)
	}

	client, err := abm.CreateJWTClient(t.Context(), &abm.JWTConfig{ClientID: "expired-client", PrivateKey: newKey(t)})
	if err != nil {
		t.Fatalf("CreateJWTClient() error = %v", err)
	}

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
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expired cache file was not purged")
	}
}

func TestTokenExchangeSignsJWT(t *testing.T) {
	client, err := abm.CreateJWTClient(t.Context(), &abm.JWTConfig{
		ClientID:   "exchange-client",
		PrivateKey: newKey(t),
		KeyID:      "key-id",
	})
	if err != nil {
		t.Fatalf("CreateJWTClient() error = %v", err)
	}

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
