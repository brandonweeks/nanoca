package nanoca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-jose/go-jose/v4"
)

type authenticatedPOST struct {
	postAsGet bool
	body      []byte
	url       string
	jwk       *jose.JSONWebKey
	accountID string // For kid-based requests
}

// keyExtractor is a function that returns a JSONWebKey based on input from a
// user-provided JSONWebSignature, for instance by extracting it from the input,
// or by looking it up in a database based on the input.
type keyExtractor func(*http.Request, *jose.JSONWebSignature) (*jose.JSONWebKey, *Problem)

var (
	ErrNonceNotFound = errors.New("nonce not found")
	ErrNonceExpired  = errors.New("nonce expired")
)

type NonceValidationError struct {
	Err error
}

func (e *NonceValidationError) Error() string {
	return fmt.Sprintf("nonce validation failed: %v", e.Err)
}

func (e *NonceValidationError) Unwrap() error {
	return e.Err
}

func (e *NonceValidationError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

func isNonceError(err error) bool {
	var nonceValidationErr *NonceValidationError
	return errors.As(err, &nonceValidationErr)
}

func (ca *CA) handleDirectory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// RFC 8555 Section 7.1.1: Directory resource does not require authentication
	// and MUST support GET requests
	if r.Method != http.MethodGet {
		ca.writeProblem(ctx, w, MethodNotAllowed("Only GET method is allowed"))
		return
	}

	dir := Directory{
		NewNonce:   ca.url("/new-nonce"),
		NewAccount: ca.url("/new-account"),
		NewOrder:   ca.url("/new-order"),
		Meta: &Meta{
			ExternalAccountRequired: false,
		},
	}

	ca.writeJSONResponse(ctx, w, http.StatusOK, dir, "")
}

func (ca *CA) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// RFC 8555 Section 7.2: "To get a fresh nonce, the client sends a HEAD request to the newNonce
	// resource on the server. The server's response MUST include a Replay-
	// Nonce header field containing a fresh nonce and SHOULD have status
	// code 200 (OK). The server MUST also respond to GET requests for this
	// resource, returning an empty body (while still providing a Replay-
	// Nonce header) with a status code of 204 (No Content)."
	if r.Method != http.MethodHead && r.Method != http.MethodGet {
		ca.writeProblem(ctx, w, MethodNotAllowed("Only HEAD and GET methods are allowed"))
		return
	}

	nonce, err := ca.generateNonce(ctx)
	if err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to generate nonce"))
		return
	}

	w.Header().Set("Replay-Nonce", nonce)
	// RFC 8555 Section 7.2: "The server MUST include a Cache-Control header field with
	// the 'no-store' directive in responses for the newNonce resource, in
	// order to prevent caching of this resource."
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (ca *CA) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse and verify JWS (requiring embedded JWK for new account)
	// RFC 8555 Section 7.3: "A client creates a new account with the server by sending a POST
	// request to the server's newAccount URL."
	// RFC 8555 Section 6.2: "For newAccount requests...there MUST be a 'jwk' field."
	postData, prob := ca.verifyPOST(r, ca.extractJWK)
	if prob != nil {
		ca.writeProblem(ctx, w, prob)
		return
	}

	var accountReq AccountRequest
	if len(postData.body) > 0 {
		if err := json.Unmarshal(postData.body, &accountReq); err != nil {
			ca.writeProblem(ctx, w, Malformed("Invalid account request"))
			return
		}
	}

	keyHash, err := ca.computeJWKHash(postData.jwk)
	if err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to process key"))
		return
	}

	existingAccount, err := ca.storage.GetAccountByKey(ctx, keyHash)
	if err == nil {
		ctx = WithAccountID(ctx, existingAccount.ID)
		if existingAccount.Orders == "" {
			existingAccount.Orders = ca.url(fmt.Sprintf("/account/%s/orders", existingAccount.ID))
			if err := ca.storage.UpdateAccount(ctx, existingAccount); err != nil {
				ca.logger.ErrorContext(ctx, "Failed to update account orders URL", "error", err)
			}
		}

		accountURL := ca.url(fmt.Sprintf("/account/%s", existingAccount.ID))
		w.Header().Set("Location", accountURL)
		ca.writeJSONResponseWithNonce(ctx, w, http.StatusOK, existingAccount)
		return
	}

	if accountReq.OnlyReturnExisting {
		ca.writeProblem(ctx, w, AccountDoesNotExist("Account does not exist"))
		return
	}

	accountID := ca.generateAccountID()
	ctx = WithAccountID(ctx, accountID)

	jwkBytes, err := json.Marshal(postData.jwk)
	if err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to serialize account key"))
		return
	}

	account := &Account{
		ID:                   accountID,
		Key:                  postData.jwk,
		KeyBytes:             jwkBytes, // Store the actual JWK JSON data
		Status:               "valid",
		Contact:              accountReq.Contact,
		TermsOfServiceAgreed: accountReq.TermsOfServiceAgreed,
		Orders:               ca.url(fmt.Sprintf("/account/%s/orders", accountID)),
		CreatedAt:            time.Now(),
	}

	if err := ca.storage.CreateAccount(ctx, account); err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to create account"))
		return
	}

	ca.logger.InfoContext(ctx, "Account created")

	accountURL := ca.url(fmt.Sprintf("/account/%s", accountID))
	w.Header().Set("Location", accountURL)
	ca.writeJSONResponseWithNonce(ctx, w, http.StatusCreated, account)
}

func (ca *CA) extractJWK(_ *http.Request, jws *jose.JSONWebSignature) (*jose.JSONWebKey, *Problem) {
	header := jws.Signatures[0].Header
	key := header.JSONWebKey
	if key == nil {
		return nil, Malformed("No JWK in JWS header")
	}
	if !key.Valid() {
		return nil, Malformed("Invalid JWK in JWS header")
	}
	// RFC 8555 Section 6.2: "The 'jwk' and 'kid' fields are mutually exclusive. Servers MUST
	// reject requests that contain both."
	if header.KeyID != "" {
		return nil, Malformed("jwk and kid header fields are mutually exclusive")
	}
	return key, nil
}

func (ca *CA) lookupJWK(r *http.Request, jws *jose.JSONWebSignature) (*jose.JSONWebKey, *Problem) {
	header := jws.Signatures[0].Header
	// RFC 8555 Section 6.2: "For all other requests, the request is signed using an existing
	// account, and there MUST be a 'kid' field. This field MUST contain
	// the account URL received by POSTing to the newAccount resource."
	accountURL := header.KeyID
	if accountURL == "" {
		return nil, Malformed("No key ID (kid) in JWS header")
	}

	accountID, err := ca.extractAccountIDFromKid(accountURL)
	if err != nil {
		return nil, Malformed("Invalid account URL format")
	}

	ctx := r.Context()
	account, err := ca.getAccount(ctx, accountID)
	if err != nil {
		ca.logger.DebugContext(ctx, "Account lookup failed", "account_id", accountID, "error", err)
		return nil, AccountDoesNotExist("Account not found")
	}

	if account.Key == nil {
		ca.logger.ErrorContext(ctx, "Account key is nil", "account_id", accountID)
		return nil, InternalServerError("Failed to process account key")
	}

	// RFC 8555 Section 6.2: "The 'jwk' and 'kid' fields are mutually exclusive. Servers MUST
	// reject requests that contain both."
	if header.JSONWebKey != nil {
		return nil, Malformed("jwk and kid header fields are mutually exclusive")
	}

	return account.Key, nil
}

func (ca *CA) verifyPOST(r *http.Request, kx keyExtractor) (*authenticatedPOST, *Problem) {
	// RFC 8555 Section 6.3: "Except for the cases described in this section, if the
	// server receives a GET request, it MUST return an error with status
	// code 405 (Method Not Allowed) and type 'malformed'."
	// Note: The allowed GET endpoints (directory, newNonce) don't use verifyPOST
	if r.Method != http.MethodPost {
		return nil, MethodNotAllowed("Only POST method is allowed for authenticated ACME endpoints")
	}

	// RFC 8555 Section 6.2: "Because client requests in ACME carry JWS objects in the Flattened
	// JSON Serialization, they must have the Content-Type header field set
	// to 'application/jose+json'. If a request does not meet this
	// requirement, then the server MUST return a response with status code
	// 415 (Unsupported Media Type)."
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/jose+json" {
		return nil, UnsupportedMediaTypeProblem("Invalid content type: expected application/jose+json")
	}

	if r.Body == nil {
		return nil, Malformed("Request body is required")
	}

	const maxBodySize = 1 << 20 // 1 MiB
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodySize)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, RequestTooLarge("Request body too large")
		}
		return nil, InternalServerError("Failed to read request body")
	}

	if len(bodyBytes) == 0 {
		return nil, Malformed("Empty request body")
	}

	body := string(bodyBytes)

	jws, err := ca.parseJWS(body)
	if err != nil {
		if prob, ok := errors.AsType[*Problem](err); ok {
			return nil, prob
		}
		return nil, Malformed(fmt.Sprintf("Failed to parse JWS: %v", err))
	}

	pubKey, prob := kx(r, jws)
	if prob != nil {
		return nil, prob
	}

	result, err := ca.verifyJWSWithKey(jws, pubKey, r)
	if err != nil {
		if isNonceError(err) {
			return nil, BadNonce(err.Error())
		}
		return nil, Malformed(fmt.Sprintf("JWS verification failed: %v", err))
	}

	return result, nil
}

func (ca *CA) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// RFC 8555 Section 7.4: "A client requests a certificate by submitting a newOrder request
	// to the newOrder resource of the server."
	if r.Method != http.MethodPost {
		ca.writeProblem(ctx, w, MethodNotAllowed("Only POST method is allowed"))
		return
	}

	postData, prob := ca.verifyPOST(r, ca.lookupJWK)
	if prob != nil {
		ca.writeProblem(ctx, w, prob)
		return
	}
	ctx = WithAccountID(ctx, postData.accountID)

	var orderReq OrderRequest
	if err := json.Unmarshal(postData.body, &orderReq); err != nil {
		ca.writeProblem(ctx, w, Malformed("Invalid order request"))
		return
	}

	if len(orderReq.Identifiers) == 0 {
		ca.writeProblem(ctx, w, Malformed("At least one identifier required"))
		return
	}

	order, err := ca.createOrder(ctx, postData.accountID, orderReq)
	if err != nil {
		ca.writeProblem(ctx, w, Malformed("Failed to create order"))
		return
	}
	ctx = WithOrderID(ctx, order.ID)

	ca.logger.InfoContext(ctx, "Order created", "identifiers", len(orderReq.Identifiers))

	orderURL := ca.url(fmt.Sprintf("/order/%s", order.ID))
	w.Header().Set("Location", orderURL)
	ca.writeJSONResponseWithNonce(ctx, w, http.StatusCreated, order)
}

func (ca *CA) handleOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	orderID := ca.extractPathSegment(r.URL.Path, "/order/")
	if orderID == "" {
		ca.writeProblem(ctx, w, Malformed("Order ID required"))
		return
	}
	ctx = WithOrderID(ctx, strings.TrimSuffix(orderID, "/finalize"))

	if strings.HasSuffix(orderID, "/finalize") {
		orderID = orderID[:len(orderID)-len("/finalize")]

		postData, prob := ca.verifyPOST(r, ca.lookupJWK)
		if prob != nil {
			ca.writeProblem(ctx, w, prob)
			return
		}
		ctx = WithAccountID(ctx, postData.accountID)

		ca.handleOrderFinalize(ctx, w, orderID, postData.accountID, postData)
		return
	}

	postData, prob := ca.verifyPOST(r, ca.lookupJWK)
	if prob != nil {
		ca.writeProblem(ctx, w, prob)
		return
	}
	ctx = WithAccountID(ctx, postData.accountID)

	order, err := ca.storage.GetOrder(ctx, orderID)
	if err != nil {
		ca.writeProblem(ctx, w, Malformed("Order not found"))
		return
	}

	if order.AccountID != postData.accountID {
		ca.writeProblem(ctx, w, Unauthorized("Order does not belong to account"))
		return
	}

	if postData.postAsGet {
		ca.writeJSONResponseWithNonce(ctx, w, http.StatusOK, order)
	} else {
		ca.writeProblem(ctx, w, Malformed("Unsupported order operation"))
	}
}

func (ca *CA) handleOrderFinalize(ctx context.Context, w http.ResponseWriter, orderID, accountID string, postData *authenticatedPOST) {
	var finalizeReq FinalizeRequest
	if err := json.Unmarshal(postData.body, &finalizeReq); err != nil {
		ca.writeProblem(ctx, w, Malformed("Invalid finalize request"))
		return
	}

	if err := ca.finalizeCertificate(ctx, orderID, accountID, finalizeReq.CSR); err != nil {
		ca.writeProblem(ctx, w, Malformed("Failed to finalize certificate"))
		return
	}

	order, err := ca.storage.GetOrder(ctx, orderID)
	if err != nil {
		ca.writeProblem(ctx, w, Malformed("Order not found"))
		return
	}

	orderCopy := *order

	ca.writeJSONResponseWithNonce(ctx, w, http.StatusOK, &orderCopy)
}

func (ca *CA) handleAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authzID := ca.extractPathSegment(r.URL.Path, "/authz/")
	if authzID == "" {
		ca.writeProblem(ctx, w, Malformed("Authorization ID required"))
		return
	}

	postData, prob := ca.verifyPOST(r, ca.lookupJWK)
	if prob != nil {
		ca.writeProblem(ctx, w, prob)
		return
	}
	ctx = WithAccountID(ctx, postData.accountID)

	authz, err := ca.storage.GetAuthorization(ctx, authzID)
	if err != nil {
		ca.writeProblem(ctx, w, Malformed("Authorization not found"))
		return
	}
	ctx = WithOrderID(ctx, authz.OrderID)

	if authz.AccountID != postData.accountID {
		ca.writeProblem(ctx, w, Unauthorized("Authorization does not belong to account"))
		return
	}

	if postData.postAsGet {
		ca.writeJSONResponseWithNonce(ctx, w, http.StatusOK, authz)
	} else {
		ca.writeProblem(ctx, w, Malformed("Authorization deactivation is not supported"))
	}
}

func (ca *CA) handleChallenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	challengeID := ca.extractPathSegment(r.URL.Path, "/challenge/")
	if challengeID == "" {
		ca.writeProblem(ctx, w, Malformed("Challenge ID required"))
		return
	}

	postData, prob := ca.verifyPOST(r, ca.lookupJWK)
	if prob != nil {
		ca.writeProblem(ctx, w, prob)
		return
	}
	ctx = WithAccountID(ctx, postData.accountID)

	challenge, err := ca.storage.GetChallenge(ctx, challengeID)
	if err != nil {
		ca.writeProblem(ctx, w, Malformed("Challenge not found"))
		return
	}

	authz, err := ca.storage.GetAuthorization(ctx, challenge.AuthzID)
	if err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Authorization not found for challenge"))
		return
	}
	ctx = WithOrderID(ctx, authz.OrderID)

	if authz.AccountID != postData.accountID {
		ca.writeProblem(ctx, w, Unauthorized("Challenge does not belong to account"))
		return
	}

	if postData.postAsGet {
		ca.writeJSONResponseWithNonce(ctx, w, http.StatusOK, challenge)
	} else {
		ca.handleChallengeResponse(ctx, w, challenge, postData)
	}
}

func (ca *CA) handleCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	certID := ca.extractPathSegment(r.URL.Path, "/certificate/")
	if certID == "" {
		ca.writeProblem(ctx, w, Malformed("Certificate ID required"))
		return
	}

	postData, prob := ca.verifyPOST(r, ca.lookupJWK)
	if prob != nil {
		ca.writeProblem(ctx, w, prob)
		return
	}
	ctx = WithAccountID(ctx, postData.accountID)

	cert, err := ca.storage.GetCertificate(ctx, certID)
	if err != nil {
		ca.writeProblem(ctx, w, Malformed("Certificate not found"))
		return
	}

	orders, err := ca.storage.GetOrdersByAccount(ctx, postData.accountID)
	if err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to get orders"))
		return
	}

	var order *Order
	for _, o := range orders {
		if o.Certificate == ca.url(fmt.Sprintf("/certificate/%s", certID)) {
			order = o
			break
		}
	}

	if order == nil || order.AccountID != postData.accountID {
		ca.writeProblem(ctx, w, Unauthorized("Certificate does not belong to this account"))
		return
	}
	ctx = WithOrderID(ctx, order.ID)

	nonce, err := ca.generateNonce(ctx)
	if err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to generate nonce"))
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Header().Set("Replay-Nonce", nonce)
	w.WriteHeader(http.StatusOK)

	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	_, _ = w.Write(pemCert)
}

func (ca *CA) writeJSONResponse(ctx context.Context, w http.ResponseWriter, statusCode int, data any, nonce string) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(data); err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to encode response"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if nonce != "" {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.WriteHeader(statusCode)

	if _, err := buf.WriteTo(w); err != nil {
		ca.logger.ErrorContext(ctx, "Failed to write JSON response", "error", err)
	}
}

func (ca *CA) writeJSONResponseWithNonce(ctx context.Context, w http.ResponseWriter, statusCode int, data any) {
	nonce, err := ca.generateNonce(ctx)
	if err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to generate nonce"))
		return
	}
	ca.writeJSONResponse(ctx, w, statusCode, data, nonce)
}

func (ca *CA) writeProblem(ctx context.Context, w http.ResponseWriter, prob *Problem) {
	if prob.Status >= 500 {
		ca.logger.ErrorContext(ctx, "Server error", "status", prob.Status, "type", prob.Type, "detail", prob.Detail)
	} else {
		ca.logger.WarnContext(ctx, "Client error", "status", prob.Status, "type", prob.Type, "detail", prob.Detail)
	}

	// RFC 8555 Section 6.5: "The server MUST include a Replay-Nonce header field in every
	// successful response to a POST request and SHOULD provide it in error responses as well."
	// RFC 8555 Section 6.5: "An error response with the 'badNonce' error type MUST include
	// a Replay-Nonce header field with a fresh nonce that the server will accept in a retry
	// of the original query"
	if nonce, err := ca.generateNonce(ctx); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(prob.Status)
	if err := json.NewEncoder(w).Encode(prob); err != nil {
		ca.logger.ErrorContext(ctx, "Failed to encode problem response", "error", err)
		// Can't call writeProblem here as it would cause recursion
		// Just log the error and let the response complete
	}
}

func (ca *CA) validateNonce(ctx context.Context, nonce string) error {
	if _, err := ca.storage.ConsumeNonce(ctx, nonce, ca.nonceExpiry); err != nil {
		if errors.Is(err, ErrNonceNotFound) {
			ca.logger.ErrorContext(ctx, "Nonce not found")
			return &NonceValidationError{Err: ErrNonceNotFound}
		}
		if errors.Is(err, ErrNonceExpired) {
			ca.logger.ErrorContext(ctx, "Nonce expired")
			return &NonceValidationError{Err: ErrNonceExpired}
		}

		ca.logger.ErrorContext(ctx, "Failed to consume nonce", "error", err)
		return &NonceValidationError{Err: fmt.Errorf("failed to consume nonce: %w", err)}
	}
	return nil
}

func (ca *CA) extractAccountIDFromKid(kid string) (string, error) {
	// Kid should be in format: {baseURL}{prefix}/account/{accountID}
	expectedPrefix := ca.url("/account") + "/"
	if len(kid) <= len(expectedPrefix) || !strings.HasPrefix(kid, expectedPrefix) {
		return "", errors.New("invalid account URL format")
	}
	return kid[len(expectedPrefix):], nil
}

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand.Read failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (ca *CA) generateAccountID() string       { return randomID(16) }
func (ca *CA) generateOrderID() string         { return randomID(16) }
func (ca *CA) generateAuthorizationID() string { return randomID(16) }
func (ca *CA) generateChallengeID() string     { return randomID(16) }
func (ca *CA) generateToken() string           { return randomID(32) }

func (ca *CA) computeJWKHash(jwk *jose.JSONWebKey) (string, error) {
	// Use JWK thumbprint as recommended by ACME spec
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to compute JWK thumbprint: %w", err)
	}

	return string(thumbprint), nil
}

func (ca *CA) createOrder(ctx context.Context, accountID string, orderReq OrderRequest) (*Order, error) {
	if _, err := ca.getAccount(ctx, accountID); err != nil {
		return nil, fmt.Errorf("account not found: %w", err)
	}

	orderID := ca.generateOrderID()

	var authzURLs []string

	for _, identifier := range orderReq.Identifiers {
		authzID := ca.generateAuthorizationID()
		authzURL := ca.url(fmt.Sprintf("/authz/%s", authzID))
		authzURLs = append(authzURLs, authzURL)

		expires := time.Now().Add(24 * time.Hour)
		authz := &Authorization{
			ID:         authzID,
			AccountID:  accountID,
			OrderID:    orderID,
			Identifier: identifier,
			Status:     "pending",
			Expires:    &expires,
			Challenges: []Challenge{},
			CreatedAt:  time.Now(),
		}

		if identifier.Type == "permanent-identifier" || identifier.Type == "hardware-module" {
			challengeID := ca.generateChallengeID()
			challenge := Challenge{
				ID:      challengeID,
				AuthzID: authzID,
				Type:    "device-attest-01",
				Status:  "pending",
				Token:   ca.generateToken(),
				URL:     ca.url(fmt.Sprintf("/challenge/%s", challengeID)),
			}

			if err := ca.storage.CreateChallenge(ctx, &challenge); err != nil {
				return nil, fmt.Errorf("failed to create challenge: %w", err)
			}
			authz.Challenges = append(authz.Challenges, challenge)
		}

		if err := ca.storage.CreateAuthorization(ctx, authz); err != nil {
			return nil, fmt.Errorf("failed to create authorization: %w", err)
		}
	}

	order := &Order{
		ID:             orderID,
		AccountID:      accountID,
		Status:         "pending",
		Identifiers:    orderReq.Identifiers,
		Authorizations: authzURLs,
		Finalize:       ca.url(fmt.Sprintf("/order/%s/finalize", orderID)),
		CreatedAt:      time.Now(),
	}

	if err := ca.storage.CreateOrder(ctx, order); err != nil {
		return nil, fmt.Errorf("failed to create order: %w", err)
	}
	return order, nil
}

func (ca *CA) handleChallengeResponse(ctx context.Context, w http.ResponseWriter, challenge *Challenge, postData *authenticatedPOST) {
	var challengeResp ChallengeRequest
	if err := json.Unmarshal(postData.body, &challengeResp); err != nil {
		ca.logger.ErrorContext(ctx, "Failed to parse challenge response", "error", err)
		ca.writeProblem(ctx, w, Malformed("Invalid challenge response"))
		return
	}

	if challenge.Type != ChallengeTypeDeviceAttest01 {
		ca.logger.ErrorContext(ctx, "Invalid challenge type for attestation", "challenge_type", challenge.Type)
		ca.writeProblem(ctx, w, Malformed("Challenge does not support device attestation"))
		return
	}

	if challengeResp.AttObj == "" {
		ca.logger.ErrorContext(ctx, "No attestation object provided in challenge response")
		ca.writeProblem(ctx, w, Malformed("Attestation object (attObj) required for device-attest-01 challenge"))
		return
	}

	attObjBytes, err := base64.RawURLEncoding.DecodeString(challengeResp.AttObj)
	if err != nil {
		ca.logger.ErrorContext(ctx, "Failed to decode attestation object", "error", err)
		ca.writeProblem(ctx, w, Malformed("Invalid base64url encoding in attestation object"))
		return
	}

	var attObj AttestationObject
	if err := cbor.Unmarshal(attObjBytes, &attObj); err != nil {
		ca.logger.ErrorContext(ctx, "Failed to parse CBOR attestation object", "error", err)
		ca.writeProblem(ctx, w, Malformed("Invalid CBOR attestation object format"))
		return
	}

	if attObj.Format == "" {
		ca.logger.ErrorContext(ctx, "Missing attestation format in attestation object")
		ca.writeProblem(ctx, w, Malformed("Attestation format (fmt) is required"))
		return
	}

	verifier, exists := ca.verifiers[attObj.Format]
	if !exists {
		ca.logger.ErrorContext(ctx, "No verifier available for attestation format", "format", attObj.Format)
		ca.writeProblem(ctx, w, Malformed("Unsupported attestation format"))
		return
	}

	stmt := AttestationStatement{
		Format:  attObj.Format,
		AttStmt: attObj.AttStmt,
	}

	if err := ca.storage.SetChallengeProcessing(ctx, challenge.ID); err != nil {
		ca.logger.ErrorContext(ctx, "Failed to update challenge status to processing", "error", err)
		ca.writeProblem(ctx, w, InternalServerError("Failed to update challenge status"))
		return
	}

	deviceInfo, err := verifier.Verify(ctx, stmt, []byte(challenge.Token))
	if err != nil {
		ca.logger.ErrorContext(ctx, "Attestation verification failed", "challenge_id", challenge.ID, "error", err)

		now := time.Now()
		prob := Unauthorized("Attestation verification failed")

		if updateErr := ca.storage.SetChallengeInvalid(ctx, challenge.ID, now, prob); updateErr != nil {
			ca.logger.ErrorContext(ctx, "Failed to update challenge status after verification failure", "error", updateErr)
		}

		ca.updateAuthorizationStatus(ctx, challenge.AuthzID)

		ca.writeProblem(ctx, w, prob)
		return
	}

	authorized, err := ca.authorizer.Authorize(ctx, deviceInfo)
	if err != nil {
		ca.logger.ErrorContext(ctx, "Device authorization check failed", "challenge_id", challenge.ID, "error", err)

		now := time.Now()
		prob := InternalServerError("Authorization check failed")

		if updateErr := ca.storage.SetChallengeInvalid(ctx, challenge.ID, now, prob); updateErr != nil {
			ca.logger.ErrorContext(ctx, "Failed to update challenge status after authorization error", "error", updateErr)
		}

		ca.updateAuthorizationStatus(ctx, challenge.AuthzID)

		ca.writeProblem(ctx, w, InternalServerError("Device authorization check failed"))
		return
	}

	if !authorized {
		ca.logger.WarnContext(ctx, "Device not authorized", "challenge_id", challenge.ID)

		now := time.Now()
		prob := Unauthorized("Device not authorized for certificate issuance")

		if updateErr := ca.storage.SetChallengeInvalid(ctx, challenge.ID, now, prob); updateErr != nil {
			ca.logger.ErrorContext(ctx, "Failed to update challenge status after authorization denial", "error", updateErr)
		}

		ca.updateAuthorizationStatus(ctx, challenge.AuthzID)

		ca.writeProblem(ctx, w, prob)
		return
	}

	now := time.Now()
	if err := ca.storage.SetChallengeValid(ctx, challenge.ID, now, attObj.AttStmt); err != nil {
		ca.logger.ErrorContext(ctx, "Failed to update challenge status to valid", "error", err)
		ca.writeProblem(ctx, w, InternalServerError("Failed to update challenge status"))
		return
	}

	ca.logger.InfoContext(ctx, "Challenge validated", "challenge_id", challenge.ID, "type", challenge.Type)

	ca.updateAuthorizationStatus(ctx, challenge.AuthzID)

	challenge, err = ca.storage.GetChallenge(ctx, challenge.ID)
	if err != nil {
		ca.logger.ErrorContext(ctx, "Failed to re-fetch challenge after validation", "error", err)
		ca.writeProblem(ctx, w, InternalServerError("Failed to retrieve challenge"))
		return
	}
	ca.writeJSONResponseWithNonce(ctx, w, http.StatusOK, challenge)
}

func (ca *CA) updateOrderStatus(ctx context.Context, order *Order) {
	if order.Status == OrderStatusValid || order.Status == OrderStatusInvalid {
		return // Final states
	}

	allValid := true
	anyInvalid := false

	for _, authzURL := range order.Authorizations {
		authzID := extractIDFromURL(authzURL, "/authz/")
		authz, err := ca.storage.GetAuthorization(ctx, authzID)
		if err != nil {
			allValid = false
			continue
		}

		if authz.Status == AuthzStatusInvalid {
			anyInvalid = true
			break
		}
		if authz.Status != AuthzStatusValid {
			allValid = false
		}
	}

	oldStatus := order.Status
	if anyInvalid {
		order.Status = OrderStatusInvalid
	} else if allValid {
		order.Status = OrderStatusReady
	}

	if oldStatus != order.Status {
		ca.logger.DebugContext(ctx, "Order status changed", "order_id", order.ID, "old_status", oldStatus, "new_status", order.Status)
	}

	if err := ca.storage.UpdateOrder(ctx, order); err != nil {
		ca.logger.ErrorContext(ctx, "Failed to update order status", "error", err)
	}
}

func (ca *CA) updateAuthorizationStatus(ctx context.Context, authzID string) {
	authz, err := ca.storage.GetAuthorization(ctx, authzID)
	if err != nil {
		return
	}

	if authz.Status == AuthzStatusValid || authz.Status == AuthzStatusInvalid {
		return // Final states
	}

	allValid := true
	anyInvalid := false

	for i, challenge := range authz.Challenges {
		currentChallenge, err := ca.storage.GetChallenge(ctx, challenge.ID)
		if err != nil {
			allValid = false
			continue
		}

		authz.Challenges[i] = *currentChallenge

		if currentChallenge.Status == "invalid" {
			anyInvalid = true
			break
		}
		if currentChallenge.Status != "valid" {
			allValid = false
		}
	}

	oldStatus := authz.Status
	if anyInvalid {
		authz.Status = AuthzStatusInvalid
	} else if allValid {
		authz.Status = AuthzStatusValid
	}

	if oldStatus != authz.Status {
		ca.logger.DebugContext(ctx, "Authorization status changed", "authz_id", authzID, "old_status", oldStatus, "new_status", authz.Status)
	}

	if err := ca.storage.UpdateAuthorization(ctx, authz); err != nil {
		ca.logger.ErrorContext(ctx, "Failed to update authorization status", "error", err)
	}

	if oldStatus != authz.Status && authz.OrderID != "" {
		if order, err := ca.storage.GetOrder(ctx, authz.OrderID); err == nil {
			ca.updateOrderStatus(ctx, order)
		}
	}
}

func (ca *CA) finalizeCertificate(ctx context.Context, orderID, accountID string, csrB64 string) error {
	// Decode base64url-encoded CSR DER
	// RFC 8555 Section 7.4: "csr (required, string): A CSR encoding the parameters for the
	// certificate being requested [RFC2986]. The CSR is sent in the
	// base64url-encoded version of the DER format."
	csrDER, err := base64.RawURLEncoding.DecodeString(csrB64)
	if err != nil {
		return fmt.Errorf("invalid CSR base64url encoding: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return BadCSR(fmt.Sprintf("CSR signature verification failed: %s", err.Error()))
	}

	order, err := ca.storage.GetOrder(ctx, orderID)
	if err != nil {
		return errors.New("order not found")
	}

	if order.AccountID != accountID {
		return errors.New("order does not belong to account")
	}

	if order.Status != OrderStatusReady {
		return errors.New("order is not ready for finalization")
	}

	var deviceInfos []*DeviceInfo
	for _, authzURL := range order.Authorizations {
		authzID := extractIDFromURL(authzURL, "/authz/")
		authz, err := ca.storage.GetAuthorization(ctx, authzID)
		if err != nil || authz.Status != AuthzStatusValid {
			continue
		}

		for _, challenge := range authz.Challenges {
			if challenge.Status == ChallengeStatusValid {
				challengeObj, err := ca.storage.GetChallenge(ctx, challenge.ID)
				if err == nil && challengeObj != nil {
					deviceInfo, err := ca.extractDeviceInfoFromChallenge(ctx, challengeObj)
					if err == nil && deviceInfo != nil {
						deviceInfos = append(deviceInfos, deviceInfo)
					}
				}
				break
			}
		}
	}

	cert, err := ca.certificateIssuer.IssueCertificate(csr, deviceInfos)
	if err != nil {
		return fmt.Errorf("failed to issue certificate: %w", err)
	}

	if err := ca.storage.CreateCertificate(ctx, cert); err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	order.Status = OrderStatusValid
	order.Certificate = ca.url(fmt.Sprintf("/certificate/%s", cert.SerialNumber))
	if err := ca.storage.UpdateOrder(ctx, order); err != nil {
		return fmt.Errorf("failed to update order: %w", err)
	}

	ca.logger.InfoContext(ctx, "Certificate issued", "serial_number", cert.SerialNumber)
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	ca.logger.DebugContext(ctx, "Issued certificate", "certificate_pem", string(pemCert))

	if len(ca.observers) > 0 {
		var primaryDeviceInfo *DeviceInfo
		if len(deviceInfos) > 0 {
			primaryDeviceInfo = deviceInfos[0]
		}

		event := &IssuanceEvent{
			Timestamp:   time.Now(),
			DeviceInfo:  primaryDeviceInfo,
			Certificate: cert,
			AccountID:   accountID,
			OrderID:     orderID,
			Metadata: map[string]any{
				"subject":       csr.Subject.String(),
				"device_count":  len(deviceInfos),
				"serial_number": cert.SerialNumber,
			},
		}

		var errs []error
		for _, observer := range ca.observers {
			if err := observer.OnIssuance(ctx, event); err != nil {
				errs = append(errs, fmt.Errorf("observer failed: %w", err))
			}
		}
		if len(errs) > 0 {
			combinedErr := errors.Join(errs...)
			ca.logger.ErrorContext(ctx, "One or more issuance observers failed", "error", combinedErr, "serial_number", cert.SerialNumber)
		}
	}

	return nil
}

func (ca *CA) extractDeviceInfoFromChallenge(ctx context.Context, challenge *Challenge) (*DeviceInfo, error) {
	if challenge.Attestation == nil {
		return nil, errors.New("no attestation data in challenge")
	}

	format, ok := challenge.Attestation["fmt"].(string)
	if !ok {
		return nil, errors.New("attestation format not found")
	}

	verifier, exists := ca.verifiers[format]
	if !exists {
		return nil, fmt.Errorf("no verifier for format: %s", format)
	}

	stmt := AttestationStatement{
		Format:  format,
		AttStmt: challenge.Attestation,
	}

	deviceInfo, err := verifier.Verify(ctx, stmt, []byte(challenge.Token))
	if err != nil {
		return nil, fmt.Errorf("failed to verify attestation: %w", err)
	}

	return deviceInfo, nil
}

func extractIDFromURL(url, prefix string) string {
	if idx := strings.LastIndex(url, prefix); idx != -1 {
		return url[idx+len(prefix):]
	}
	return ""
}
