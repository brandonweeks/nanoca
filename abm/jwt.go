package abm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// TokenSource is an oauth2.TokenSource that caches its access token in
// memory until the token expires or Expire is called.
type TokenSource struct {
	src *assertionTokenSource

	// fetching serializes token exchanges. It is a channel so a caller
	// waiting on another caller's exchange can give up when its context
	// ends.
	fetching chan struct{}

	mu  sync.Mutex
	tok *oauth2.Token
}

// NewTokenSource returns a token source that signs a client assertion with
// config.PrivateKey and exchanges it for an access token at config.TokenURL.
// The exchange is sent with httpClient, or http.DefaultClient if nil.
func NewTokenSource(httpClient *http.Client, config TokenConfig) (*TokenSource, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: config.PrivateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", config.KeyID),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT signer: %w", err)
	}
	return &TokenSource{
		src: &assertionTokenSource{
			httpClient: httpClient,
			config:     config,
			signer:     signer,
		},
		fetching: make(chan struct{}, 1),
	}, nil
}

// Token is TokenContext with a background context. It lets TokenSource be
// used as an oauth2.TokenSource.
func (s *TokenSource) Token() (*oauth2.Token, error) {
	return s.TokenContext(context.Background())
}

// TokenContext returns the cached token, or fetches a new one under ctx if
// there is none or it has expired.
func (s *TokenSource) TokenContext(ctx context.Context) (*oauth2.Token, error) {
	if tok := s.cached(); tok != nil {
		return tok, nil
	}
	select {
	case s.fetching <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-s.fetching }()
	if tok := s.cached(); tok != nil {
		return tok, nil
	}

	tok, err := s.src.token(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tok = tok
	return tok, nil
}

// cached returns the cached token, or nil if there is none or it has
// expired.
func (s *TokenSource) cached() *oauth2.Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok.Valid() {
		return s.tok
	}
	return nil
}

// Expire drops tok from the cache so the next Token call fetches a new one.
// It does nothing if tok has already been replaced.
func (s *TokenSource) Expire(tok *oauth2.Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok == tok {
		s.tok = nil
	}
}

func (c *TokenConfig) validate() error {
	switch {
	case c.ClientID == "":
		return errors.New("client ID is required")
	case c.KeyID == "":
		return errors.New("key ID is required")
	case c.PrivateKey == nil:
		return errors.New("private key is required")
	case !isP256(c.PrivateKey):
		return errors.New("private key must be a P-256 ECDSA key")
	case c.TokenURL == "":
		return errors.New("token URL is required")
	case c.Scope == "":
		return errors.New("scope is required")
	}
	return nil
}

func isP256(key crypto.Signer) bool {
	pub, ok := key.Public().(*ecdsa.PublicKey)
	return ok && pub.Curve == elliptic.P256()
}

// assertionTokenSource exchanges a freshly signed client assertion for a
// token on every call.
type assertionTokenSource struct {
	httpClient *http.Client
	config     TokenConfig
	signer     jose.Signer
}

func (s *assertionTokenSource) token(ctx context.Context) (*oauth2.Token, error) {
	assertion, err := s.createJWT()
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT: %w", err)
	}

	cc := &clientcredentials.Config{
		ClientID:  s.config.ClientID,
		TokenURL:  s.config.TokenURL,
		Scopes:    []string{s.config.Scope},
		AuthStyle: oauth2.AuthStyleInParams,
		EndpointParams: url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {assertion},
		},
	}
	return cc.Token(context.WithValue(ctx, oauth2.HTTPClient, s.httpClient))
}

// createJWT creates and signs a JWT for the client assertion
func (s *assertionTokenSource) createJWT() (string, error) {
	jwtID, err := generateJWTID()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT ID: %w", err)
	}

	now := time.Now()
	claims := jwt.Claims{
		Subject:  s.config.ClientID,
		Audience: jwt.Audience{assertionAudience},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(10 * time.Minute)),
		Issuer:   s.config.ClientID,
		ID:       jwtID,
	}

	rawJWT, err := jwt.Signed(s.signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return rawJWT, nil
}

// generateJWTID generates a unique JWT ID using crypto/rand
func generateJWTID() (string, error) {
	bytes := make([]byte, 16) // 128-bit random value
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
