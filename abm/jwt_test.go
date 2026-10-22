package abm_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

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

func tokenConfig(t *testing.T, tokenURL string) abm.TokenConfig {
	t.Helper()
	return abm.TokenConfig{
		ClientID:   "client-id",
		KeyID:      "key-id",
		PrivateKey: newKey(t),
		TokenURL:   tokenURL,
		Scope:      "test.api",
	}
}

// tokenServer is a fake token endpoint that checks the client assertion
// and hands out access tokens named tok-1, tok-2, ...
type tokenServer struct {
	*httptest.Server
	exchanges atomic.Int32
}

func newTokenServer(t *testing.T, config func() abm.TokenConfig) *tokenServer {
	t.Helper()
	ts := &tokenServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := config()
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		for key, want := range map[string]string{
			"grant_type":            "client_credentials",
			"client_id":             cfg.ClientID,
			"scope":                 cfg.Scope,
			"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		} {
			if got := r.PostForm.Get(key); got != want {
				t.Errorf("form %s = %q, want %q", key, got, want)
			}
		}

		tok, err := jwt.ParseSigned(r.PostForm.Get("client_assertion"), []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Errorf("ParseSigned() error = %v", err)
			http.Error(w, "bad assertion", http.StatusBadRequest)
			return
		}
		if kid := tok.Headers[0].KeyID; kid != cfg.KeyID {
			t.Errorf("kid = %q, want %q", kid, cfg.KeyID)
		}
		var claims jwt.Claims
		if err := tok.Claims(cfg.PrivateKey.Public(), &claims); err != nil {
			t.Errorf("assertion signature: %v", err)
			http.Error(w, "bad assertion", http.StatusBadRequest)
			return
		}
		if claims.Issuer != cfg.ClientID || claims.Subject != cfg.ClientID {
			t.Errorf("iss, sub = %q, %q, want %q", claims.Issuer, claims.Subject, cfg.ClientID)
		}
		if !claims.Audience.Contains("https://account.apple.com/auth/oauth2/v2/token") {
			t.Errorf("aud = %v", claims.Audience)
		}

		n := ts.exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + strconv.Itoa(int(n)) + `","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestNewTokenSourceExchangesAssertion(t *testing.T) {
	t.Parallel()

	var cfg abm.TokenConfig
	ts := newTokenServer(t, func() abm.TokenConfig { return cfg })
	cfg = tokenConfig(t, ts.URL+"/auth/oauth2/token")

	src, err := abm.NewTokenSource(ts.Client(), cfg)
	if err != nil {
		t.Fatalf("NewTokenSource() error = %v", err)
	}
	for range 2 {
		tok, err := src.Token()
		if err != nil {
			t.Fatalf("Token() error = %v", err)
		}
		if tok.AccessToken != "tok-1" {
			t.Errorf("AccessToken = %q, want tok-1", tok.AccessToken)
		}
	}
	if n := ts.exchanges.Load(); n != 1 {
		t.Errorf("token exchanges = %d, want 1", n)
	}
}

func TestNewTokenSourceValidation(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(*abm.TokenConfig){
		"client ID":   func(c *abm.TokenConfig) { c.ClientID = "" },
		"key ID":      func(c *abm.TokenConfig) { c.KeyID = "" },
		"private key": func(c *abm.TokenConfig) { c.PrivateKey = nil },
		"token URL":   func(c *abm.TokenConfig) { c.TokenURL = "" },
		"scope":       func(c *abm.TokenConfig) { c.Scope = "" },
		"P-256 key": func(c *abm.TokenConfig) {
			key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			c.PrivateKey = key
		},
		"supported key type": func(c *abm.TokenConfig) { c.PrivateKey = struct{ crypto.Signer }{newKey(t)} },
	} {
		cfg := tokenConfig(t, "https://token.invalid")
		mutate(&cfg)
		if _, err := abm.NewTokenSource(http.DefaultClient, cfg); err == nil {
			t.Errorf("NewTokenSource(missing %s) error = nil, want error", name)
		}
	}
}

func TestTokenContextHonorsCancel(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block }))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(block) })

	src, err := abm.NewTokenSource(srv.Client(), tokenConfig(t, srv.URL))
	if err != nil {
		t.Fatalf("NewTokenSource() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := src.TokenContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("TokenContext() error = %v, want deadline exceeded", err)
	}
}

func TestTokenContextHonorsCancelWhileAnotherExchangeRuns(t *testing.T) {
	t.Parallel()

	arrived := make(chan struct{}, 1)
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		arrived <- struct{}{}
		<-block
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(block) })

	src, err := abm.NewTokenSource(srv.Client(), tokenConfig(t, srv.URL))
	if err != nil {
		t.Fatalf("NewTokenSource() error = %v", err)
	}
	go func() { _, _ = src.TokenContext(context.Background()) }()
	<-arrived

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := src.TokenContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("TokenContext() error = %v, want deadline exceeded", err)
	}
}
