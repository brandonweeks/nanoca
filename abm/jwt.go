package abm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// cachedToken represents a token stored in the disk cache
type cachedToken struct {
	Token     *oauth2.Token `json:"token"`
	Created   time.Time     `json:"created"`
	ExpiresAt time.Time     `json:"expires_at"`
}

// isValid checks if the cached token is still valid
func (ct *cachedToken) isValid() bool {
	return time.Now().Before(ct.ExpiresAt) && ct.Token.Valid()
}

// jwtAssertionTokenSource implements oauth2.TokenSource with fresh JWT generation for each request
type jwtAssertionTokenSource struct {
	config     *JWTConfig
	baseConfig *clientcredentials.Config
	cacheDir   string
}

// Token generates a fresh JWT and exchanges it for an OAuth2 token, using disk cache when available
func (j *jwtAssertionTokenSource) Token() (*oauth2.Token, error) {
	if cachedToken, err := j.loadCachedToken(); err == nil && cachedToken != nil {
		return cachedToken, nil
	}

	jwtToken, err := j.createJWT()
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT: %w", err)
	}

	j.baseConfig.EndpointParams["client_assertion"] = []string{jwtToken}

	tokenSource := j.baseConfig.TokenSource(context.TODO())
	token, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}

	if err := j.saveCachedToken(token); err != nil {
		return nil, fmt.Errorf("failed to cache token: %w", err)
	}

	return token, nil
}

// getCacheFilePath returns the file path for caching tokens for this client
func (j *jwtAssertionTokenSource) getCacheFilePath() string {
	hash := sha256.Sum256([]byte(j.config.ClientID))
	filename := hex.EncodeToString(hash[:8]) + ".json"
	return filepath.Join(j.cacheDir, filename)
}

// loadCachedToken attempts to load a cached token from disk
func (j *jwtAssertionTokenSource) loadCachedToken() (*oauth2.Token, error) {
	cachePath := j.getCacheFilePath()

	cleanCachePath, err := filepath.Abs(filepath.Clean(cachePath))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve cache path: %w", err)
	}
	cleanCacheDir, err := filepath.Abs(filepath.Clean(j.cacheDir))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve cache directory: %w", err)
	}
	relPath, err := filepath.Rel(cleanCacheDir, cleanCachePath)
	if err != nil || filepath.IsAbs(relPath) || len(relPath) >= 3 && relPath[:3] == ".."+string(filepath.Separator) {
		return nil, errors.New("invalid cache path: outside cache directory")
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read cached token: %w", err)
	}

	var cached cachedToken
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached token: %w", err)
	}

	if !cached.isValid() {
		_ = os.Remove(cachePath)
		return nil, nil
	}

	return cached.Token, nil
}

// saveCachedToken saves a token to disk cache with 1-week expiry
func (j *jwtAssertionTokenSource) saveCachedToken(token *oauth2.Token) error {
	if err := os.MkdirAll(j.cacheDir, 0o750); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	cached := cachedToken{
		Token:     token,
		Created:   time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}

	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("failed to marshal cached token: %w", err)
	}

	cachePath := j.getCacheFilePath()
	if err := os.WriteFile(cachePath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write cached token: %w", err)
	}

	return nil
}

// createJWT creates and signs a JWT for the client assertion
func (j *jwtAssertionTokenSource) createJWT() (string, error) {
	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       j.config.PrivateKey,
	}

	signerOpts := &jose.SignerOptions{}
	signerOpts = signerOpts.WithType("JWT")
	if j.config.KeyID != "" {
		signerOpts = signerOpts.WithHeader("kid", j.config.KeyID)
	}

	signer, err := jose.NewSigner(signingKey, signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT signer: %w", err)
	}

	jwtID, err := generateJWTID()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT ID: %w", err)
	}

	now := time.Now()
	claims := jwt.Claims{
		Subject:  j.config.ClientID,
		Audience: jwt.Audience{"https://account.apple.com/auth/oauth2/v2/token"},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(10 * time.Minute)),
		Issuer:   j.config.ClientID,
		ID:       jwtID,
	}

	builder := jwt.Signed(signer).Claims(claims)
	rawJWT, err := builder.Serialize()
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

// CreateJWTClient creates an HTTP client configured for JWT-based authentication
func CreateJWTClient(ctx context.Context, config *JWTConfig) (*http.Client, error) {
	baseConfig := &clientcredentials.Config{
		ClientID: config.ClientID,
		TokenURL: tokenURL,
		Scopes:   []string{scope},
		EndpointParams: url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {""}, // Will be populated by jwtAssertionTokenSource
		},
	}

	cacheDir := filepath.Join(".nanoca_cache", "abm_tokens")

	tokenSource := &jwtAssertionTokenSource{
		config:     config,
		baseConfig: baseConfig,
		cacheDir:   cacheDir,
	}

	return oauth2.NewClient(ctx, oauth2.ReuseTokenSource(nil, tokenSource)), nil
}
