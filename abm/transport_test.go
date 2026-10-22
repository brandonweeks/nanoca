package abm_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca/abm"
)

// newAPIServer returns a server that rejects every access token except
// accept, and echoes the request body back on success.
func newAPIServer(t *testing.T, accept string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+accept {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.Copy(w, r.Body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTransportClient(t *testing.T) (*http.Client, *tokenServer) {
	t.Helper()
	var cfg abm.TokenConfig
	ts := newTokenServer(t, func() abm.TokenConfig { return cfg })
	cfg = tokenConfig(t, ts.URL)

	src, err := abm.NewTokenSource(ts.Client(), cfg)
	if err != nil {
		t.Fatalf("NewTokenSource() error = %v", err)
	}
	return &http.Client{Transport: &abm.Transport{Source: src}}, ts
}

func TestTransportRetriesAfter401(t *testing.T) {
	t.Parallel()

	client, ts := newTransportClient(t)
	api := newAPIServer(t, "tok-2")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, api.URL, strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "payload" {
		t.Errorf("replayed body = %q, want payload", body)
	}
	if n := ts.exchanges.Load(); n != 2 {
		t.Errorf("token exchanges = %d, want 2", n)
	}
}

func TestTransportRetriesOnce(t *testing.T) {
	t.Parallel()

	client, ts := newTransportClient(t)
	api := newAPIServer(t, "never")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, api.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if n := ts.exchanges.Load(); n != 2 {
		t.Errorf("token exchanges = %d, want 2", n)
	}
}

func TestTransportSkipsRetryWithoutGetBody(t *testing.T) {
	t.Parallel()

	client, ts := newTransportClient(t)
	api := newAPIServer(t, "tok-2")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, api.URL, io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if n := ts.exchanges.Load(); n != 1 {
		t.Errorf("token exchanges = %d, want 1", n)
	}
}

func TestTransportExpiresTokenAfter401WithoutGetBody(t *testing.T) {
	t.Parallel()

	client, ts := newTransportClient(t)
	var requests atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer tok-2" {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(api.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, api.URL, io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	_ = resp.Body.Close()

	if resp := get(t.Context(), t, client, api.URL); resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if n := requests.Load(); n != 2 {
		t.Errorf("API requests = %d, want 2", n)
	}
	if n := ts.exchanges.Load(); n != 2 {
		t.Errorf("token exchanges = %d, want 2", n)
	}
}

// newRateLimitedServer returns a server that answers 429 with the given
// Retry-After header to the first limited requests, then echoes the body.
func newRateLimitedServer(t *testing.T, limited int32, retryAfter string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) <= limited {
			w.Header().Set("Retry-After", retryAfter)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = io.Copy(w, r.Body)
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func TestTransportRetriesAfter429(t *testing.T) {
	t.Parallel()

	client, _ := newTransportClient(t)
	api, requests := newRateLimitedServer(t, 2, "0")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, api.URL, strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK || string(body) != "payload" {
		t.Errorf("response = %d %q, want 200 payload", resp.StatusCode, body)
	}
	if n := requests.Load(); n != 3 {
		t.Errorf("requests = %d, want 3", n)
	}
}

func TestTransportGivesUpAfter429Retries(t *testing.T) {
	t.Parallel()

	client, _ := newTransportClient(t)
	api, requests := newRateLimitedServer(t, 100, "0")

	resp := get(t.Context(), t, client, api.URL)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", resp.StatusCode)
	}
	if n := requests.Load(); n != 4 {
		t.Errorf("requests = %d, want 4", n)
	}
}

func TestTransportReturns429WhenWaitIsTooLong(t *testing.T) {
	t.Parallel()

	client, _ := newTransportClient(t)

	t.Run("over max", func(t *testing.T) {
		t.Parallel()
		api, requests := newRateLimitedServer(t, 1, "3600")
		if resp := get(t.Context(), t, client, api.URL); resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("status = %d, want 429", resp.StatusCode)
		}
		if n := requests.Load(); n != 1 {
			t.Errorf("requests = %d, want 1", n)
		}
	})

	t.Run("past deadline", func(t *testing.T) {
		t.Parallel()
		api, requests := newRateLimitedServer(t, 1, "30")
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if resp := get(ctx, t, client, api.URL); resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("status = %d, want 429", resp.StatusCode)
		}
		if n := requests.Load(); n != 1 {
			t.Errorf("requests = %d, want 1", n)
		}
	})
}

func TestTransportWaitHonorsCancel(t *testing.T) {
	t.Parallel()

	client, _ := newTransportClient(t)
	api, _ := newRateLimitedServer(t, 1, "30")

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := client.Do(req); !errors.Is(err, context.Canceled) {
		if resp != nil {
			_ = resp.Body.Close()
		}
		t.Errorf("Do() error = %v, want context.Canceled", err)
	}
}

func get(ctx context.Context, t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	_ = resp.Body.Close()
	return resp
}
