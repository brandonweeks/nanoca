package nanoca

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/go-jose/go-jose/v4"
)

// supportedJWSAlgorithms defines the signature algorithms supported by this ACME server.
// RFC 8555 Section 6.2: "An ACME server MUST implement the 'ES256' signature algorithm."
var supportedJWSAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256,
}

func getSupportedAlgorithmStrings() []string {
	algorithms := make([]string, len(supportedJWSAlgorithms))
	for i, alg := range supportedJWSAlgorithms {
		algorithms[i] = string(alg)
	}
	return algorithms
}

func isMACalgorithm(alg string) bool {
	// List of known MAC/HMAC algorithms from JOSE registry
	macAlgorithms := []string{
		"HS256", "HS384", "HS512", // HMAC using SHA-2
		"HS256K", "HS384K", "HS512K", // HMAC using SHA-3
	}

	if slices.Contains(macAlgorithms, alg) {
		return true
	}

	if len(alg) >= 2 && alg[:2] == "HS" {
		return true
	}

	return false
}

func (ca *CA) parseJWS(body string) (*jose.JSONWebSignature, error) {
	// Parse the raw JWS JSON to check that:
	// * the unprotected Header field is not being used.
	// * the "signatures" member isn't present, just "signature".
	//
	// This must be done prior to `jose.parseSigned` since it will strip away
	// these headers.
	var unprotected struct {
		Header     map[string]string
		Signatures []any
		Payload    *string `json:"payload"` // Pointer to detect missing payload (detached)
		Protected  string  `json:"protected"`
	}
	if err := json.Unmarshal([]byte(body), &unprotected); err != nil {
		return nil, Malformed(fmt.Sprint("Parse error reading JWS: ", err.Error()))
	}

	// RFC 8555 Section 6.2: "The JWS Unprotected Header [RFC7515] MUST NOT be used"
	if unprotected.Header != nil {
		return nil, Malformed("JWS must not contain unprotected header")
	}

	// RFC 8555 Section 6.2: "The JWS MUST be in the Flattened JSON Serialization [RFC7515]"
	// This means using "signature" not "signatures" array
	if len(unprotected.Signatures) > 0 {
		return nil, Malformed("JWS must not contain signatures member, only signature")
	}

	// RFC 8555 Section 6.2: "The JWS Payload MUST NOT be detached"
	if unprotected.Payload == nil {
		return nil, Malformed("JWS payload must not be detached")
	}

	// RFC 8555 Section 6.2
	if unprotected.Protected != "" {
		protectedBytes, err := base64.RawURLEncoding.DecodeString(unprotected.Protected)
		if err == nil {
			var protectedHeader map[string]any
			if err := json.Unmarshal(protectedBytes, &protectedHeader); err == nil {
				if b64, exists := protectedHeader["b64"]; exists {
					if b64Value, ok := b64.(bool); ok && !b64Value {
						return nil, Malformed("JWS unencoded payload option (b64=false) must not be used")
					}
				}

				// RFC 8555 Section 6.2: "This field MUST NOT contain 'none' or a Message
				// Authentication Code (MAC) algorithm (e.g. one in which the algorithm
				// registry description mentions MAC/HMAC)."
				if alg, exists := protectedHeader["alg"]; exists {
					if algStr, ok := alg.(string); ok {
						if algStr == "none" {
							return nil, BadSignatureAlgorithm("Algorithm 'none' is not allowed", getSupportedAlgorithmStrings())
						}
						if isMACalgorithm(algStr) {
							return nil, BadSignatureAlgorithm(fmt.Sprintf("MAC algorithm '%s' is not allowed", algStr), getSupportedAlgorithmStrings())
						}
					}
				}
			}
		}
	}

	jws, err := jose.ParseSigned(body, supportedJWSAlgorithms)
	if err != nil {
		if _, ok := errors.AsType[*jose.ErrUnexpectedSignatureAlgorithm](err); ok {
			return nil, BadSignatureAlgorithm("JWS contains unexpected signature algorithm", getSupportedAlgorithmStrings())
		}
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	// RFC 8555 Section 6.2: "The JWS MUST NOT have multiple signatures"
	if len(jws.Signatures) > 1 {
		return nil, Malformed("JWS must not contain multiple signatures")
	}

	if len(jws.Signatures) == 0 {
		return nil, Malformed("JWS must contain at least one signature")
	}

	return jws, nil
}

// RFC 8555 Section 6.2
func (ca *CA) validateJWSStructure(jws *jose.JSONWebSignature) error {
	if len(jws.Signatures) == 0 {
		return errors.New("JWS must have at least one signature")
	}
	if len(jws.Signatures) > 1 {
		return errors.New("JWS must not have multiple signatures")
	}

	return nil
}

// RFC 8555 Section 6.4
func (ca *CA) validateRequestURL(jwsURL string, r *http.Request) error {
	if r.TLS == nil {
		return errors.New("HTTPS is required")
	}

	expectedURL := fmt.Sprintf("https://%s%s", r.Host, r.URL.Path)

	if jwsURL != expectedURL {
		return fmt.Errorf("JWS url header %q does not match request URL %q", jwsURL, expectedURL)
	}

	return nil
}

func (ca *CA) verifyJWSWithKey(jws *jose.JSONWebSignature, pubKey *jose.JSONWebKey, r *http.Request) (*authenticatedPOST, error) {
	if err := ca.validateJWSStructure(jws); err != nil {
		return nil, fmt.Errorf("invalid JWS structure: %w", err)
	}

	signature := jws.Signatures[0]
	header := signature.Protected

	nonce := signature.Protected.Nonce
	if nonce == "" {
		return nil, errors.New("missing or invalid nonce header")
	}

	url, ok := signature.Protected.ExtraHeaders[jose.HeaderKey("url")].(string)
	if !ok || url == "" {
		return nil, errors.New("missing or invalid url header")
	}

	if err := ca.validateRequestURL(url, r); err != nil {
		return nil, fmt.Errorf("URL validation failed: %w", err)
	}

	// RFC 8555 Section 6.5
	if err := ca.validateNonce(r.Context(), nonce); err != nil {
		return nil, fmt.Errorf("nonce validation failed: %w", err)
	}

	payload, err := jws.Verify(pubKey)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	result := &authenticatedPOST{
		jwk:       pubKey,
		url:       url,
		body:      payload,
		postAsGet: len(payload) == 0,
	}

	// If this is a kid-based request, extract account ID
	if header.KeyID != "" {
		accountID, err := ca.extractAccountIDFromKid(header.KeyID)
		if err != nil {
			return nil, fmt.Errorf("invalid kid: %w", err)
		}
		result.accountID = accountID
	}

	return result, nil
}

func (ca *CA) getAccount(ctx context.Context, accountID string) (*Account, error) {
	account, err := ca.storage.GetAccount(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get account %s: %w", accountID, err)
	}
	return account, nil
}
