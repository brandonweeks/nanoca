package abm_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/brandonweeks/nanoca/abm"
)

func TestNewValidation(t *testing.T) {
	t.Parallel()

	if _, err := abm.New(nil); err == nil {
		t.Error("New(nil) error = nil, want error")
	}
	if _, err := abm.New(&abm.Config{Token: tokenConfig(t, abm.BusinessTokenURL)}); err == nil {
		t.Error("New(config without BaseURL) error = nil, want error")
	}
	if _, err := abm.New(&abm.Config{BaseURL: abm.BusinessBaseURL}); err == nil {
		t.Error("New(config without Token) error = nil, want error")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	cfg := &abm.Config{
		BaseURL: abm.BusinessBaseURL,
		Token: abm.TokenConfig{
			ClientID:   "client-id",
			KeyID:      "key-id",
			PrivateKey: newKey(t),
			TokenURL:   abm.BusinessTokenURL,
			Scope:      abm.BusinessScope,
		},
	}
	if _, err := abm.New(cfg); err != nil {
		t.Fatalf("New() error = %v", err)
	}
}

func TestNewUsesHTTPClient(t *testing.T) {
	t.Parallel()

	var cfg abm.TokenConfig
	ts := newTokenServer(t, func() abm.TokenConfig { return cfg })
	cfg = tokenConfig(t, ts.URL)

	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"type":"orgDevices","id":"A","attributes":{"serialNumber":"A"}}]}`))
	}))
	t.Cleanup(api.Close)

	// Only this client trusts the API server's test certificate.
	httpClient := api.Client()
	transport := httpClient.Transport

	client, err := abm.New(&abm.Config{BaseURL: api.URL + "/v1", HTTPClient: httpClient, Token: cfg})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	devices, err := client.GetOrganizationDevices(t.Context())
	if err != nil {
		t.Fatalf("GetOrganizationDevices() error = %v", err)
	}
	if len(devices) != 1 || devices[0].SerialNumber != "A" {
		t.Errorf("devices = %+v, want serial A", devices)
	}
	if httpClient.Transport != transport {
		t.Error("New modified the caller's HTTP client")
	}
}

func TestNewKeepsRedirectsOnAPIHost(t *testing.T) {
	t.Parallel()

	var cfg abm.TokenConfig
	ts := newTokenServer(t, func() abm.TokenConfig { return cfg })
	cfg = tokenConfig(t, ts.URL)

	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
	}))
	t.Cleanup(other.Close)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/same/orgDevices":
			http.Redirect(w, r, "/v1/orgDevices", http.StatusFound)
		case "/other/orgDevices":
			http.Redirect(w, r, other.URL+"/v1/orgDevices", http.StatusFound)
		default:
			_, _ = w.Write([]byte(`{"data":[{"type":"orgDevices","id":"A","attributes":{"serialNumber":"A"}}]}`))
		}
	}))
	t.Cleanup(api.Close)

	same, err := abm.New(&abm.Config{BaseURL: api.URL + "/same", HTTPClient: ts.Client(), Token: cfg})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if devices, err := same.GetOrganizationDevices(t.Context()); err != nil || len(devices) != 1 {
		t.Errorf("GetOrganizationDevices() via same-host redirect = %+v, %v", devices, err)
	}

	off, err := abm.New(&abm.Config{BaseURL: api.URL + "/other", HTTPClient: ts.Client(), Token: cfg})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := off.GetOrganizationDevices(t.Context()); err == nil {
		t.Error("GetOrganizationDevices() via off-host redirect error = nil, want error")
	}
	if leaked.Load() {
		t.Error("access token sent to a host the API redirected to")
	}
}
