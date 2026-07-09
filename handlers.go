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
	"slices"
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

// lookupProblem maps a storage lookup failure to a client-facing problem: a
// missing object is the client's error, anything else is the server's.
func lookupProblem(err error, resource string) *Problem {
	if errors.Is(err, ErrNotFound) {
		return Malformed(resource + " not found")
	}
	return InternalServerError("Failed to get " + strings.ToLower(resource)).WithCause(err)
}

// lostRace reports whether a conditional storage write was
// rejected because another request has settled the record; the winner's
// result stands. Missing either sentinel would misread a lost race as a
// backend failure.
func lostRace(err error) bool {
	return errors.Is(err, ErrReserved) || errors.Is(err, ErrStatusMismatch)
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
		ca.writeProblem(ctx, w, InternalServerError("Failed to generate nonce").WithCause(err))
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

	keyThumbprint, err := jwkThumbprint(postData.jwk)
	if err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to process key").WithCause(err))
		return
	}

	existingAccount, err := ca.storage.GetAccountByKey(ctx, keyThumbprint)
	if err != nil && !errors.Is(err, ErrNotFound) {
		ca.writeProblem(ctx, w, InternalServerError("Failed to look up account").WithCause(err))
		return
	}
	if err == nil {
		ca.writeExistingAccount(ctx, w, existingAccount)
		return
	}

	if accountReq.OnlyReturnExisting {
		ca.writeProblem(ctx, w, AccountDoesNotExist("Account does not exist"))
		return
	}

	accountID := ca.generateAccountID()
	ctx = WithAccountID(ctx, accountID)

	account := &Account{
		ID:                   accountID,
		Key:                  postData.jwk,
		KeyThumbprint:        keyThumbprint,
		Status:               "valid",
		Contact:              accountReq.Contact,
		TermsOfServiceAgreed: accountReq.TermsOfServiceAgreed,
		Orders:               ca.url(fmt.Sprintf("/account/%s/orders", accountID)),
		CreatedAt:            time.Now(),
	}

	if err := ca.storage.CreateAccount(ctx, account); err != nil {
		// Lost a race with a concurrent registration; return the winner.
		if errors.Is(err, ErrAccountExists) {
			if existing, err := ca.storage.GetAccountByKey(ctx, keyThumbprint); err == nil {
				ca.writeExistingAccount(ctx, w, existing)
				return
			}
		}
		ca.writeProblem(ctx, w, InternalServerError("Failed to create account"))
		return
	}

	ca.logger.InfoContext(ctx, "Account created")

	accountURL := ca.url(fmt.Sprintf("/account/%s", accountID))
	w.Header().Set("Location", accountURL)
	ca.writeJSONResponseWithNonce(ctx, w, http.StatusCreated, account)
}

// RFC 8555 Section 7.3: an already-registered key gets a 200 with the
// existing account URL in Location, rather than a 201.
func (ca *CA) writeExistingAccount(ctx context.Context, w http.ResponseWriter, account *Account) {
	ctx = WithAccountID(ctx, account.ID)
	if account.Orders == "" {
		account.Orders = ca.url(fmt.Sprintf("/account/%s/orders", account.ID))
		if err := ca.storage.UpdateAccount(ctx, account); err != nil {
			ca.logger.ErrorContext(ctx, "Failed to update account orders URL", "error", err)
		}
	}

	w.Header().Set("Location", ca.url(fmt.Sprintf("/account/%s", account.ID)))
	ca.writeJSONResponseWithNonce(ctx, w, http.StatusOK, account)
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
		if errors.Is(err, ErrNotFound) {
			return nil, AccountDoesNotExist("Account not found")
		}
		return nil, InternalServerError("Failed to look up account")
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
		return nil, InternalServerError("Failed to read request body").WithCause(err)
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
		if prob, ok := errors.AsType[*Problem](err); ok {
			return nil, prob
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

	// Only attestable identifier types get a challenge in createOrder; any
	// other type would yield an authorization with no challenges, which
	// nothing could ever validate.
	for _, identifier := range orderReq.Identifiers {
		if identifier.Type != IdentifierTypePermanentIdentifier && identifier.Type != IdentifierTypeHardwareModule {
			ca.writeProblem(ctx, w, UnsupportedIdentifier(fmt.Sprintf("Unsupported identifier type %q", identifier.Type)))
			return
		}
	}

	order, err := ca.createOrder(ctx, postData.accountID, orderReq)
	if err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to create order").WithCause(err))
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
	finalize := strings.HasSuffix(orderID, "/finalize")
	orderID = strings.TrimSuffix(orderID, "/finalize")
	ctx = WithOrderID(ctx, orderID)

	postData, prob := ca.verifyPOST(r, ca.lookupJWK)
	if prob != nil {
		ca.writeProblem(ctx, w, prob)
		return
	}
	ctx = WithAccountID(ctx, postData.accountID)

	if finalize {
		ca.handleOrderFinalize(ctx, w, orderID, postData)
		return
	}

	order, err := ca.storage.GetOrder(ctx, orderID)
	if err != nil {
		ca.writeProblem(ctx, w, lookupProblem(err, "Order"))
		return
	}

	if order.AccountID != postData.accountID {
		ca.writeProblem(ctx, w, Unauthorized("Order does not belong to account"))
		return
	}

	// A settled authorization whose pending-to-ready promotion failed has
	// nothing left to retry it — re-POSTs of the valid challenge
	// short-circuit and updateAuthorizationStatus returns early on final
	// states — so recompute on poll; the guarded transition keeps this
	// from overwriting a status another request has since written.
	if order.Status == OrderStatusPending {
		ca.updateOrderStatus(ctx, order)
	}

	// A crash mid-finalize leaves the order processing in storage, and an
	// RFC 8555 Section 7.1.6 client polls processing without re-submitting
	// finalize; once the reservation lapses the order must read as ready
	// again so a retry can reclaim it.
	order.presentLapsed(ca.reservationLease)

	if postData.postAsGet {
		ca.writeJSONResponseWithNonce(ctx, w, http.StatusOK, order)
	} else {
		ca.writeProblem(ctx, w, Malformed("Unsupported order operation"))
	}
}

func (ca *CA) handleOrderFinalize(ctx context.Context, w http.ResponseWriter, orderID string, postData *authenticatedPOST) {
	var finalizeReq FinalizeRequest
	if err := json.Unmarshal(postData.body, &finalizeReq); err != nil {
		ca.writeProblem(ctx, w, Malformed("Invalid finalize request"))
		return
	}

	order, err := ca.finalizeCertificate(ctx, orderID, postData.accountID, finalizeReq.CSR)
	if err != nil {
		if prob, ok := errors.AsType[*Problem](err); ok {
			ca.writeProblem(ctx, w, prob)
		} else {
			ca.writeProblem(ctx, w, InternalServerError("Failed to finalize certificate").WithCause(err))
		}
		return
	}

	ca.writeJSONResponseWithNonce(ctx, w, http.StatusOK, order)
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
		ca.writeProblem(ctx, w, lookupProblem(err, "Authorization"))
		return
	}
	ctx = WithOrderID(ctx, authz.OrderID)

	if authz.AccountID != postData.accountID {
		ca.writeProblem(ctx, w, Unauthorized("Authorization does not belong to account"))
		return
	}

	// A settled challenge whose authorization promotion write was lost has
	// nothing left to retry it — re-POSTs of a settled challenge
	// short-circuit — so recompute on poll, as handleOrder does for
	// pending orders.
	ca.updateAuthorizationStatus(ctx, authz)

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
		ca.writeProblem(ctx, w, lookupProblem(err, "Challenge"))
		return
	}

	authz, err := ca.storage.GetAuthorization(ctx, challenge.AuthzID)
	if err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to get authorization for challenge").WithCause(err))
		return
	}
	ctx = WithOrderID(ctx, authz.OrderID)

	if authz.AccountID != postData.accountID {
		ca.writeProblem(ctx, w, Unauthorized("Challenge does not belong to account"))
		return
	}

	// A crash mid-validation leaves the challenge processing in storage,
	// and an RFC 8555 Section 7.1.6 client polls after responding once
	// rather than re-POSTing; once the reservation lapses the challenge
	// must read as pending again so the client can respond anew.
	challenge.presentLapsed(ca.reservationLease)

	if postData.postAsGet {
		ca.writeJSONResponseWithNonce(ctx, w, http.StatusOK, challenge)
		return
	}

	// RFC 8555 Section 7.1.6: valid and invalid are final, so a repeat POST
	// reports the state instead of failing. A processing challenge falls
	// through: the reserve answers duplicates with the current state while
	// its lease is live, and lets a retry reclaim an interrupted validation
	// once it lapses.
	if challenge.Status == ChallengeStatusValid || challenge.Status == ChallengeStatusInvalid {
		// The short-circuit skips the recompute a fresh validation would
		// run, so a promotion lost to a transient write failure would
		// otherwise never retry.
		ca.updateAuthorizationStatus(ctx, authz)
		ca.writeJSONResponseWithNonce(ctx, w, http.StatusOK, challenge)
		return
	}

	ca.handleChallengeResponse(ctx, w, challenge, authz, postData)
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
		ca.writeProblem(ctx, w, lookupProblem(err, "Certificate"))
		return
	}

	orders, err := ca.storage.GetOrdersByAccount(ctx, postData.accountID)
	if err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to get orders").WithCause(err))
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
		ca.writeProblem(ctx, w, InternalServerError("Failed to generate nonce").WithCause(err))
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Header().Set("Replay-Nonce", nonce)
	w.WriteHeader(http.StatusOK)

	for _, raw := range cert.ServedChain() {
		if err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: raw}); err != nil {
			ca.logger.ErrorContext(ctx, "Failed to write certificate chain", "error", err)
			return
		}
	}
}

// scrubStorageState strips storage-internal state — the reservation and the
// stored attestation object — from a client-facing copy; the ACME wire
// format has neither field.
func scrubStorageState(data any) any {
	switch v := data.(type) {
	case *Order:
		scrubbed := *v
		scrubbed.Reservation = nil
		return &scrubbed
	case *Challenge:
		scrubbed := *v
		scrubbed.Reservation = nil
		scrubbed.Attestation = nil
		return &scrubbed
	case *Authorization:
		scrubbed := *v
		scrubbed.Challenges = slices.Clone(v.Challenges)
		for i := range scrubbed.Challenges {
			scrubbed.Challenges[i].Reservation = nil
			scrubbed.Challenges[i].Attestation = nil
		}
		return &scrubbed
	}
	return data
}

func (ca *CA) writeJSONResponse(ctx context.Context, w http.ResponseWriter, statusCode int, data any, nonce string) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(scrubStorageState(data)); err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to encode response").WithCause(err))
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
		ca.writeProblem(ctx, w, InternalServerError("Failed to generate nonce").WithCause(err))
		return
	}
	ca.writeJSONResponse(ctx, w, statusCode, data, nonce)
}

func (ca *CA) writeProblem(ctx context.Context, w http.ResponseWriter, prob *Problem) {
	attrs := []any{"status", prob.Status, "type", prob.Type, "detail", prob.Detail}
	if prob.Cause != nil {
		attrs = append(attrs, "error", prob.Cause)
	}
	if prob.Status >= 500 {
		ca.logger.ErrorContext(ctx, "Server error", attrs...)
	} else {
		ca.logger.WarnContext(ctx, "Client error", attrs...)
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

// validateNonce returns a *Problem so the badNonce/serverInternal distinction
// is made once, where the storage error is known; verifyPOST unwraps it.
func (ca *CA) validateNonce(ctx context.Context, nonce string) error {
	_, err := ca.storage.ConsumeNonce(ctx, nonce, ca.nonceExpiry)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotFound):
		ca.logger.ErrorContext(ctx, "Nonce not found")
		return BadNonce("Nonce not found")
	case errors.Is(err, ErrNonceExpired):
		ca.logger.ErrorContext(ctx, "Nonce expired")
		return BadNonce("Nonce expired")
	default:
		ca.logger.ErrorContext(ctx, "Failed to consume nonce", "error", err)
		return InternalServerError("Failed to validate nonce")
	}
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

func jwkThumbprint(jwk *jose.JSONWebKey) (string, error) {
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to compute JWK thumbprint: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// createOrder assumes the account exists: its only caller reaches it through
// lookupJWK, which has just loaded the account to authenticate the request.
func (ca *CA) createOrder(ctx context.Context, accountID string, orderReq OrderRequest) (*Order, error) {
	orderID := ca.generateOrderID()

	var authzURLs []string
	var authzs []*Authorization
	var challenges []*Challenge

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
			challenge := &Challenge{
				ID:      challengeID,
				AuthzID: authzID,
				Type:    "device-attest-01",
				Status:  "pending",
				Token:   ca.generateToken(),
				URL:     ca.url(fmt.Sprintf("/challenge/%s", challengeID)),
			}

			challenges = append(challenges, challenge)
			authz.Challenges = append(authz.Challenges, *challenge)
		}

		authzs = append(authzs, authz)
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

	if err := ca.storage.CreateOrder(ctx, order, authzs, challenges); err != nil {
		return nil, fmt.Errorf("failed to create order: %w", err)
	}
	return order, nil
}

func (ca *CA) handleChallengeResponse(ctx context.Context, w http.ResponseWriter, challenge *Challenge, authz *Authorization, postData *authenticatedPOST) {
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

	// The reservation is the persisted processing status under a lease:
	// duplicate POSTs — concurrent, cross-process, or retries within the
	// lease — are answered with the current state instead of a second
	// validation, and a validation interrupted by a crash is reclaimed by
	// a retry once the lease lapses.
	reservationToken := randomID(16)
	if err := ca.storage.ReserveChallengeValidation(ctx, challenge.ID, reservationToken, ca.reservationLease); err != nil {
		if lostRace(err) {
			ca.reportChallengeState(ctx, w, challenge.ID)
			return
		}
		ca.logger.ErrorContext(ctx, "Failed to reserve challenge for validation", "error", err)
		ca.writeProblem(ctx, w, InternalServerError("Failed to update challenge status"))
		return
	}

	deviceInfo, err := verifier.Verify(ctx, stmt, []byte(challenge.Token))
	if err != nil {
		ca.logger.ErrorContext(ctx, "Attestation verification failed", "challenge_id", challenge.ID, "error", err)
		ca.failChallenge(ctx, w, challenge, authz, reservationToken, Unauthorized("Attestation verification failed"))
		return
	}
	// A validation that proves no identity must not settle valid: finalize
	// derives the certificate's SANs from the DeviceInfo and refuses an
	// order that yields none, so accepting it here would wedge the order.
	if deviceInfo == nil {
		ca.logger.ErrorContext(ctx, "Attestation verifier returned no device identity", "challenge_id", challenge.ID, "format", attObj.Format)
		ca.failChallenge(ctx, w, challenge, authz, reservationToken, Unauthorized("Attestation yielded no device identity"))
		return
	}

	authorized, err := ca.authorizer.Authorize(ctx, deviceInfo)
	if err != nil {
		ca.logger.ErrorContext(ctx, "Device authorization check failed", "challenge_id", challenge.ID, "error", err)

		// A failed authorizer call is a backend condition, not a verdict on
		// the attestation; settle back to pending so a retry can validate
		// once it clears, instead of invalidating the challenge.
		challenge.settlePending()
		if releaseErr := ca.storage.SettleChallenge(ctx, challenge, reservationToken); releaseErr != nil {
			// A lost race means another request settled the
			// challenge; its result stands. Anything else leaves the
			// challenge processing, and it heals by lease expiry.
			if !lostRace(releaseErr) {
				ca.logger.ErrorContext(ctx, "Failed to release challenge after authorization error", "error", releaseErr)
			}
		}

		ca.writeProblem(ctx, w, InternalServerError("Device authorization check failed"))
		return
	}

	if !authorized {
		ca.logger.WarnContext(ctx, "Device not authorized", "challenge_id", challenge.ID)
		ca.failChallenge(ctx, w, challenge, authz, reservationToken, Unauthorized("Device not authorized for certificate issuance"))
		return
	}

	challenge.settleValid(time.Now(), attObjBytes)
	if err := ca.storage.SettleChallenge(ctx, challenge, reservationToken); err != nil {
		// Another writer settled the challenge first; report its result.
		if lostRace(err) {
			ca.reportChallengeState(ctx, w, challenge.ID)
			return
		}
		ca.logger.ErrorContext(ctx, "Failed to update challenge status to valid", "error", err)
		ca.writeProblem(ctx, w, InternalServerError("Failed to update challenge status"))
		return
	}

	ca.logger.InfoContext(ctx, "Challenge validated", "challenge_id", challenge.ID, "type", challenge.Type)

	ca.updateAuthorizationStatus(ctx, authz)

	ca.writeJSONResponseWithNonce(ctx, w, http.StatusOK, challenge)
}

// reportChallengeState answers a request that lost a validation race with
// the challenge's current stored state.
func (ca *CA) reportChallengeState(ctx context.Context, w http.ResponseWriter, challengeID string) {
	current, err := ca.storage.GetChallenge(ctx, challengeID)
	if err != nil {
		ca.writeProblem(ctx, w, InternalServerError("Failed to get challenge after lost validation race").WithCause(err))
		return
	}
	ca.writeJSONResponseWithNonce(ctx, w, http.StatusOK, current)
}

// failChallenge settles a reserved challenge as invalid and reports prob. A
// lost race means another request settled the challenge first: its
// result is reported instead and the recompute is left to it.
func (ca *CA) failChallenge(ctx context.Context, w http.ResponseWriter, challenge *Challenge, authz *Authorization, reservationToken string, prob *Problem) {
	challenge.settleInvalid(time.Now(), prob)
	if err := ca.storage.SettleChallenge(ctx, challenge, reservationToken); err != nil {
		if lostRace(err) {
			ca.reportChallengeState(ctx, w, challenge.ID)
			return
		}
		ca.logger.ErrorContext(ctx, "Failed to update challenge status", "error", err)
	}

	ca.updateAuthorizationStatus(ctx, authz)
	ca.writeProblem(ctx, w, prob)
}

// updateOrderStatus promotes a pending order once its authorizations settle.
// The pending-only guard — enforced again by SetOrderStatus against the
// stored record — keeps this recomputation from overwriting a status a
// concurrent finalize has since written.
func (ca *CA) updateOrderStatus(ctx context.Context, order *Order) {
	if order.Status != OrderStatusPending {
		return
	}

	// An order with no authorizations must not count as valid.
	allValid := len(order.Authorizations) > 0
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

	var next string
	switch {
	case anyInvalid:
		next = OrderStatusInvalid
	case allValid:
		next = OrderStatusReady
	default:
		return
	}

	// A mismatch means another request settled the order first; its result
	// stands.
	if err := ca.storage.SetOrderStatus(ctx, order.ID, OrderStatusPending, next); err != nil {
		if !errors.Is(err, ErrStatusMismatch) {
			ca.logger.ErrorContext(ctx, "Failed to update order status", "error", err)
		}
		return
	}

	ca.logger.DebugContext(ctx, "Order status changed", "order_id", order.ID, "old_status", order.Status, "new_status", next)
	order.Status = next
}

// updateAuthorizationStatus settles a pending authorization once its
// challenges settle, refreshing the embedded challenge copies with the
// transition. The pending-only guard — enforced again by
// SettleAuthorization against the stored record — keeps a recompute from
// stale reads from overwriting a settlement another request has since
// written; a recompute that settles nothing writes nothing.
func (ca *CA) updateAuthorizationStatus(ctx context.Context, authz *Authorization) {
	if authz.Status != AuthzStatusPending {
		return
	}

	// An authorization with no challenges must not count as valid.
	allValid := len(authz.Challenges) > 0
	anyInvalid := false

	for i, challenge := range authz.Challenges {
		currentChallenge, err := ca.storage.GetChallenge(ctx, challenge.ID)
		if err != nil {
			allValid = false
			continue
		}

		// A processing challenge whose reservation lapsed reads as pending
		// here for the same reason handleChallenge presents it that way: an
		// RFC 8555 Section 7.5.1 client polls the authorization object, and
		// a challenge shown as processing forever would never be re-POSTed.
		currentChallenge.presentLapsed(ca.reservationLease)

		// Reservations and attestation blobs belong to the challenge
		// record, not embedded copies.
		currentChallenge.Reservation = nil
		currentChallenge.Attestation = nil
		authz.Challenges[i] = *currentChallenge

		if currentChallenge.Status == "invalid" {
			anyInvalid = true
			break
		}
		if currentChallenge.Status != "valid" {
			allValid = false
		}
	}

	var next string
	switch {
	case anyInvalid:
		next = AuthzStatusInvalid
	case allValid:
		next = AuthzStatusValid
	default:
		return
	}

	// A mismatch means another request settled the authorization first;
	// its result stands.
	authz.Status = next
	if err := ca.storage.SettleAuthorization(ctx, authz); err != nil {
		authz.Status = AuthzStatusPending
		if !errors.Is(err, ErrStatusMismatch) {
			ca.logger.ErrorContext(ctx, "Failed to update authorization status", "error", err)
		}
		return
	}

	ca.logger.DebugContext(ctx, "Authorization status changed", "authz_id", authz.ID, "old_status", AuthzStatusPending, "new_status", next)

	if authz.OrderID != "" {
		if order, err := ca.storage.GetOrder(ctx, authz.OrderID); err == nil {
			ca.updateOrderStatus(ctx, order)
		}
	}
}

// parseFinalizeCSR decodes and validates the CSR from a finalize request.
// RFC 8555 Section 7.4: "csr (required, string): A CSR encoding the parameters for the
// certificate being requested [RFC2986]. The CSR is sent in the
// base64url-encoded version of the DER format."
func parseFinalizeCSR(csrB64 string) (*x509.CertificateRequest, error) {
	csrDER, err := base64.RawURLEncoding.DecodeString(csrB64)
	if err != nil {
		return nil, BadCSR("Invalid CSR base64url encoding")
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, BadCSR("Failed to parse CSR")
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, BadCSR(fmt.Sprintf("CSR signature verification failed: %s", err.Error()))
	}

	return csr, nil
}

func (ca *CA) finalizeCertificate(ctx context.Context, orderID, accountID string, csrB64 string) (*Order, error) {
	// Existence and ownership are settled before the reservation is taken,
	// so a request that has no claim on the order can never hold its lock.
	order, err := ca.storage.GetOrder(ctx, orderID)
	if err != nil {
		return nil, lookupProblem(err, "Order")
	}

	if order.AccountID != accountID {
		return nil, Unauthorized("Order does not belong to account")
	}

	// The reservation is the persisted processing status under a lease, so
	// exclusivity holds across CA processes sharing this storage, and a
	// crashed holder is reclaimable once the lease lapses. The snapshot
	// read above stays valid: readiness is judged atomically by the
	// reserve, and every field used below is immutable after CreateOrder.
	token := randomID(16)
	if err := ca.storage.ReserveOrderFinalize(ctx, orderID, token, ca.reservationLease); err != nil {
		switch {
		case errors.Is(err, ErrReserved):
			return nil, OrderNotReady("Order finalization is already in progress")
		case errors.Is(err, ErrStatusMismatch):
			return nil, OrderNotReady("Order is not ready for finalization")
		case errors.Is(err, ErrNotFound):
			return nil, lookupProblem(err, "Order")
		}
		return nil, fmt.Errorf("failed to reserve order for finalization: %w", err)
	}

	// RFC 8555 Section 7.4 conditions the orderNotReady error only on order
	// state, so the CSR is judged after the reserve has settled state and
	// ownership; a rejected CSR then releases the reservation back to ready.
	csr, err := parseFinalizeCSR(csrB64)
	if err != nil {
		return nil, ca.failOrder(ctx, orderID, token, err)
	}

	cert, deviceInfos, err := ca.issueForOrder(ctx, order, csr, token)
	if err != nil {
		return nil, err
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

	return order, nil
}

// issueForOrder issues the certificate for a reserved order under a fresh
// per-attempt ID and commits it by transitioning the order to valid. The
// token-gated order write is the commit point: a failure releases the
// reservation and leaves the signed certificate stored but referenced by
// no order, so it is never served. A retry issues a fresh certificate for
// the CSR it actually carries, so a served certificate never predates the
// CSR that finalized the order, and a crash leaves the order processing
// until the lease lapses and a retry reclaims it.
func (ca *CA) issueForOrder(ctx context.Context, order *Order, csr *x509.CertificateRequest, token string) (*Certificate, []*DeviceInfo, error) {
	deviceInfos, err := ca.deviceInfosForOrder(ctx, order)
	if err != nil {
		return nil, nil, ca.failOrder(ctx, order.ID, token, err)
	}

	cert, err := ca.certificateIssuer.IssueCertificate(ctx, csr, deviceInfos)
	if err != nil {
		return nil, nil, ca.failOrder(ctx, order.ID, token, fmt.Errorf("failed to issue certificate: %w", err))
	}
	cert.ID = randomID(16)

	order.Status = OrderStatusValid
	order.Certificate = ca.url(fmt.Sprintf("/certificate/%s", cert.ID))
	order.Reservation = nil
	if err := ca.storage.CompleteOrder(ctx, order, cert, token); err != nil {
		ca.logger.ErrorContext(ctx, "Leaving signed certificate unreferenced after failed completion", "serial_number", cert.SerialNumber, "error", err)
		// A lost race means the lease lapsed and another finalize
		// reclaimed the order; its outcome stands and there is no
		// reservation left to release. That is a client-state condition
		// like losing the reserve itself, not a backend failure: a 5xx
		// would invite a retry of a finalize that has been superseded.
		if lostRace(err) {
			return nil, nil, OrderNotReady("Order finalization was superseded by another request")
		}
		return nil, nil, ca.failOrder(ctx, order.ID, token, fmt.Errorf("failed to complete order: %w", err))
	}

	return cert, deviceInfos, nil
}

// failOrder releases the finalize reservation, distinguishing terminal
// failures from transient ones. A client-fault problem can only recur on
// retry, so the order moves to invalid per RFC 8555 Section 7.1.6 and the
// client abandons it. badCSR is the exception: only the CSR is at fault,
// and Section 7.4 has the order stay ready so an amended CSR can finalize
// it. Anything else returns the order to ready so a retry can finalize
// again.
func (ca *CA) failOrder(ctx context.Context, orderID, token string, err error) error {
	to := OrderStatusReady
	if prob, ok := errors.AsType[*Problem](err); ok && prob.Status < http.StatusInternalServerError && prob.Type != badCSRErr {
		to = OrderStatusInvalid
	}
	switch serr := ca.storage.ReleaseOrderFinalize(ctx, orderID, token, to); {
	case serr == nil:
	case lostRace(serr):
		// The lease lapsed and another finalize took over; its outcome
		// stands.
		ca.logger.DebugContext(ctx, "Finalize reservation was reclaimed", "error", serr)
	default:
		// The order stays processing and heals by lease expiry.
		ca.logger.ErrorContext(ctx, "Failed to release order after finalize failure", "error", serr)
	}
	return err
}

// deviceInfosForOrder re-derives the attested device identity for each valid
// authorization. Any failure aborts the finalize: the order only reached
// "ready" through a successful attestation, so issuing without the identity
// it proved would silently strip the SANs from the certificate. An empty
// result means no authorization reads valid — inconsistent state that may
// heal — so it is refused as retriable rather than issued identity-less.
func (ca *CA) deviceInfosForOrder(ctx context.Context, order *Order) ([]*DeviceInfo, error) {
	var deviceInfos []*DeviceInfo
	for _, authzURL := range order.Authorizations {
		authzID := extractIDFromURL(authzURL, "/authz/")
		authz, err := ca.storage.GetAuthorization(ctx, authzID)
		if err != nil {
			return nil, fmt.Errorf("failed to get authorization: %w", err)
		}
		if authz.Status != AuthzStatusValid {
			continue
		}

		for _, challenge := range authz.Challenges {
			if challenge.Status != ChallengeStatusValid {
				continue
			}
			challengeObj, err := ca.storage.GetChallenge(ctx, challenge.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to get challenge: %w", err)
			}
			deviceInfo, err := ca.extractDeviceInfoFromChallenge(ctx, challengeObj)
			if err != nil {
				return nil, fmt.Errorf("failed to extract device info: %w", err)
			}
			if deviceInfo != nil {
				deviceInfos = append(deviceInfos, deviceInfo)
			}
			break
		}
	}
	if len(deviceInfos) == 0 {
		return nil, errors.New("no valid authorization yields an attested identity")
	}
	return deviceInfos, nil
}

// extractDeviceInfoFromChallenge re-verifies the attestation stored with a
// validated challenge. A missing or undecodable stored attestation can only
// recur on retry, so those are unauthorized problems failOrder treats as
// terminal. A missing verifier is this instance's configuration and a
// re-verification failure is environmental — the statement already passed
// verification at challenge time — so both return plain errors that keep
// the order retriable.
func (ca *CA) extractDeviceInfoFromChallenge(ctx context.Context, challenge *Challenge) (*DeviceInfo, error) {
	if len(challenge.Attestation) == 0 {
		return nil, Unauthorized("No attestation recorded for challenge")
	}

	var attObj AttestationObject
	if err := cbor.Unmarshal(challenge.Attestation, &attObj); err != nil {
		return nil, Unauthorized("Stored attestation is not usable")
	}

	verifier, exists := ca.verifiers[attObj.Format]
	if !exists {
		return nil, fmt.Errorf("no verifier registered for attestation format %q", attObj.Format)
	}

	stmt := AttestationStatement{
		Format:  attObj.Format,
		AttStmt: attObj.AttStmt,
	}

	deviceInfo, err := verifier.Verify(ctx, stmt, []byte(challenge.Token))
	if err != nil {
		return nil, fmt.Errorf("failed to re-verify attestation: %w", err)
	}

	return deviceInfo, nil
}

func extractIDFromURL(url, prefix string) string {
	if idx := strings.LastIndex(url, prefix); idx != -1 {
		return url[idx+len(prefix):]
	}
	return ""
}
