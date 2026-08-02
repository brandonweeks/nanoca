package remote

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func generateP256PEM(t *testing.T) (string, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), key
}

func generateRSAPEM(t *testing.T) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestNew_validKey(t *testing.T) {
	pemStr, _ := generateP256PEM(t)
	signer, err := New("http://localhost:8080", "token", pemStr)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if signer.Public() == nil {
		t.Fatal("Public() returned nil")
	}
}

func TestNew_invalidKey(t *testing.T) {
	_, err := New("http://localhost:8080", "token", "garbage")
	if err == nil {
		t.Fatal("New() should have failed with garbage PEM")
	}
}

func TestNew_wrongKeyType(t *testing.T) {
	pemStr := generateRSAPEM(t)
	_, err := New("http://localhost:8080", "token", pemStr)
	if err == nil {
		t.Fatal("New() should have failed with RSA key")
	}
	if !strings.Contains(err.Error(), "expected ECDSA public key") {
		t.Errorf("expected error message to contain 'expected ECDSA public key', got: %v", err)
	}
}

func TestSign_success(t *testing.T) {
	pemStr, key := generateP256PEM(t)
	digest := []byte("this is a digest")
	token := "secret-token"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		decodedDigest, _ := base64.StdEncoding.DecodeString(req.Digest)
		if string(decodedDigest) != string(digest) {
			t.Errorf("digest mismatch: %s != %s", string(decodedDigest), string(digest))
		}

		sig, err := key.Sign(rand.Reader, decodedDigest, crypto.SHA256)
		if err != nil {
			t.Errorf("failed to sign: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signResponse{
			Signature: base64.StdEncoding.EncodeToString(sig),
		})
	}))
	defer ts.Close()

	signer, _ := New(ts.URL, token, pemStr)
	sig, err := signer.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Sign() returned empty signature")
	}
}

func TestSign_invalidSignature(t *testing.T) {
	pemStr, _ := generateP256PEM(t)
	// Use a different key to produce a valid DER signature that won't verify
	// against the public key the signer was constructed with.
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong key: %v", err)
	}
	digest := []byte("this is a digest")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sig, sigErr := wrongKey.Sign(rand.Reader, digest, crypto.SHA256)
		if sigErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signResponse{
			Signature: base64.StdEncoding.EncodeToString(sig),
		})
	}))
	defer ts.Close()

	signer, _ := New(ts.URL, "token", pemStr)
	_, err = signer.Sign(nil, digest, crypto.SHA256)
	if err == nil {
		t.Fatal("Sign() should have failed with wrong-key signature")
	}
	if !strings.Contains(err.Error(), "oracle returned invalid signature") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSign_oracleError(t *testing.T) {
	pemStr, _ := generateP256PEM(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("oracle error"))
	}))
	defer ts.Close()

	signer, _ := New(ts.URL, "token", pemStr)
	_, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if err == nil {
		t.Fatal("Sign() should have failed")
	}
	if !strings.Contains(err.Error(), "oracle returned 500") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSign_oracleUnauthorized(t *testing.T) {
	pemStr, _ := generateP256PEM(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer ts.Close()

	signer, _ := New(ts.URL, "token", pemStr)
	_, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if err == nil {
		t.Fatal("Sign() should have failed")
	}
	if !strings.Contains(err.Error(), "oracle returned 401") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSign_networkError(t *testing.T) {
	pemStr, _ := generateP256PEM(t)
	// Unreachable URL
	signer, _ := New("http://localhost:1", "token", pemStr)
	_, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if err == nil {
		t.Fatal("Sign() should have failed")
	}
	if !strings.Contains(err.Error(), "oracle request failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSign_malformedResponse(t *testing.T) {
	pemStr, _ := generateP256PEM(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer ts.Close()

	signer, _ := New(ts.URL, "token", pemStr)
	_, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if err == nil {
		t.Fatal("Sign() should have failed")
	}
	if !strings.Contains(err.Error(), "decoding oracle response") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSign_invalidBase64Signature(t *testing.T) {
	pemStr, _ := generateP256PEM(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signResponse{
			Signature: "not-valid-base64!@#$",
		})
	}))
	defer ts.Close()

	signer, _ := New(ts.URL, "token", pemStr)
	_, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if err == nil {
		t.Fatal("Sign() should have failed with invalid base64 signature")
	}
	if !strings.Contains(err.Error(), "decoding signature bytes") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSign_responseTooLarge(t *testing.T) {
	pemStr, _ := generateP256PEM(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Send a response larger than 1MB
		largeSignature := strings.Repeat("A", 1<<20+100)
		_ = json.NewEncoder(w).Encode(signResponse{
			Signature: largeSignature,
		})
	}))
	defer ts.Close()

	signer, _ := New(ts.URL, "token", pemStr)
	_, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if err == nil {
		t.Fatal("Sign() should have failed due to large response")
	}
	if !strings.Contains(err.Error(), "decoding oracle response") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSign_errorTooLarge(t *testing.T) {
	pemStr, _ := generateP256PEM(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		// Send an error body larger than 4KB
		_, _ = w.Write([]byte(strings.Repeat("E", 8192)))
	}))
	defer ts.Close()

	signer, _ := New(ts.URL, "token", pemStr)
	_, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if err == nil {
		t.Fatal("Sign() should have failed")
	}
	// The implementation uses LimitReader(resp.Body, 4096), so the body read is limited.
	if !strings.Contains(err.Error(), "oracle returned 500") {
		t.Errorf("unexpected error: %v", err)
	}
	errStr := err.Error()
	if len(errStr) > 5000 { // 4096 + some overhead for the message prefix
		t.Errorf("error message too long: %d bytes", len(errStr))
	}
}

func TestNew_rejectsPlaintextHTTP(t *testing.T) {
	pemStr, _ := generateP256PEM(t)
	_, err := New("http://signer.example.com", "token", pemStr)
	if err == nil {
		t.Fatal("New() should reject plain HTTP to non-loopback address")
	}
	if !strings.Contains(err.Error(), "must use HTTPS") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNew_allowsHTTPLoopback(t *testing.T) {
	pemStr, _ := generateP256PEM(t)
	for _, addr := range []string{"localhost:8080", "127.0.0.1:8080", "[::1]:8080"} {
		_, err := New("http://"+addr, "token", pemStr)
		if err != nil {
			t.Errorf("New() should allow HTTP to %s, got: %v", addr, err)
		}
	}
}

func TestNew_allowsHTTPS(t *testing.T) {
	pemStr, _ := generateP256PEM(t)
	_, err := New("https://signer.example.com", "token", pemStr)
	if err != nil {
		t.Errorf("New() should allow HTTPS, got: %v", err)
	}
}

func TestSign_errorBodySanitized(t *testing.T) {
	pemStr, _ := generateP256PEM(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		// Include control characters that could be used for log injection
		_, _ = w.Write([]byte("error\ninjected-line\r\x00hidden"))
	}))
	defer ts.Close()

	signer, _ := New(ts.URL, "token", pemStr)
	_, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if err == nil {
		t.Fatal("Sign() should have failed")
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, "\n") || strings.Contains(errMsg, "\r") || strings.Contains(errMsg, "\x00") {
		t.Errorf("error message contains unsanitized control characters: %q", errMsg)
	}
	if !strings.Contains(errMsg, "error?injected-line") {
		t.Errorf("expected sanitized error body, got: %q", errMsg)
	}
}
