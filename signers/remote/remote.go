// Package remote provides a crypto.Signer implementation that delegates
// signing operations to an authenticated HTTP signing oracle.
//
// The oracle protocol is minimal:
//
//	POST /sign
//	Authorization: Bearer <token>
//	Content-Type: application/json
//
//	Request:  {"digest": "<base64>", "hash": "<SHA-256|SHA-384|SHA-512>"}
//	Response: {"signature": "<base64-DER>"}
//
// The digest field contains the pre-hashed digest as produced by
// crypto/x509 internals — callers must not hash again.
// The signature field must be a DER-encoded ASN.1 ECDSA signature
// (not IEEE P1363 / raw r||s concatenation).
package remote

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// Signer delegates crypto.Signer operations to a remote HTTP signing oracle.
type Signer struct {
	signURL    string
	authToken  string
	publicKey  crypto.PublicKey
	httpClient *http.Client
}

// New creates a remote signer.
//
// oracleURL is the base URL of the signing oracle (e.g. https://signer.example.com).
// The URL must use HTTPS; plain HTTP is only permitted for loopback addresses
// (localhost, 127.0.0.1, ::1) to support development and testing.
// authToken is sent as a Bearer token in the Authorization header.
// publicKeyPEM is the PKIX PEM-encoded public key corresponding to the
// private key held by the oracle. It is used to satisfy crypto.Signer.Public()
// and is never sent to the oracle. After each signing operation, the returned
// signature is verified against this key before being returned to the caller.
func New(oracleURL, authToken, publicKeyPEM string) (*Signer, error) {
	if err := validateOracleURL(oracleURL); err != nil {
		return nil, fmt.Errorf("remote signer: %w", err)
	}
	signURL, err := url.JoinPath(oracleURL, "sign")
	if err != nil {
		return nil, fmt.Errorf("remote signer: building oracle URL: %w", err)
	}
	pub, err := parsePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("remote signer: parsing public key: %w", err)
	}
	return &Signer{
		signURL:   signURL,
		authToken: authToken,
		publicKey: pub,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// Public returns the public key corresponding to the private key held by the oracle.
func (s *Signer) Public() crypto.PublicKey { return s.publicKey }

type signRequest struct {
	Digest string `json:"digest"`
	Hash   string `json:"hash"`
}

type signResponse struct {
	Signature string `json:"signature"`
}

// Sign sends the digest to the oracle and returns a DER-encoded signature.
// digest is the pre-hashed digest as passed by crypto/x509 internals.
// The oracle is responsible for not hashing again.
//
// Note: the crypto.Signer interface does not accept a context, so this method
// uses context.Background(). Cancellation relies on the http.Client timeout.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("remote signer: signer opts are required")
	}

	reqBody, err := json.Marshal(signRequest{
		Digest: base64.StdEncoding.EncodeToString(digest),
		Hash:   opts.HashFunc().String(),
	})
	if err != nil {
		return nil, fmt.Errorf("remote signer: marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.signURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("remote signer: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.authToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("remote signer: oracle request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	const maxResponseSize = 1 << 20 // 1MB
	const maxErrorSize = 4096       // 4KB

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorSize))
		return nil, fmt.Errorf("remote signer: oracle returned %d: %s", resp.StatusCode, sanitizeErrorBody(body))
	}

	var sr signResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&sr); err != nil {
		return nil, fmt.Errorf("remote signer: decoding oracle response: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(sr.Signature)
	if err != nil {
		return nil, fmt.Errorf("remote signer: decoding signature bytes: %w", err)
	}

	ecPub, ok := s.publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("remote signer: public key is not ECDSA")
	}
	if !ecdsa.VerifyASN1(ecPub, digest, sig) {
		return nil, errors.New("remote signer: oracle returned invalid signature")
	}

	return sig, nil
}

// sanitizeErrorBody strips control characters from oracle error responses
// to prevent log injection.
func sanitizeErrorBody(body []byte) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != ' ' {
			return '?'
		}
		return r
	}, string(body))
}

func validateOracleURL(oracleURL string) error {
	u, err := url.Parse(oracleURL)
	if err != nil {
		return fmt.Errorf("invalid oracle URL: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}
	return errors.New("oracle URL must use HTTPS (plain HTTP is only allowed for loopback addresses)")
}

func parsePublicKeyPEM(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PKIX public key: %w", err)
	}
	if _, ok := key.(*ecdsa.PublicKey); !ok {
		return nil, fmt.Errorf("expected ECDSA public key, got %T", key)
	}
	return key, nil
}
