package apple

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
)

// expiredChain returns a statement whose chain was valid only in 2020, the
// root that signs it, and the challenge its nonce commits to.
func expiredChain(t *testing.T) (nanoca.AttestationStatement, *x509.CertPool, []byte) {
	t.Helper()

	notBefore := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(0, 3, 0)

	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test attestation root"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	challenge := []byte("challenge-token")
	nonce := sha256.Sum256(challenge)
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test attestation leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		ExtraExtensions: []pkix.Extension{
			{Id: appleDeviceSerialOID, Value: []byte("SERIAL")},
			{Id: appleChallengeNonceOID, Value: nonce[:]},
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(root)
	stmt := nanoca.AttestationStatement{
		Format:  "apple",
		AttStmt: map[string]any{"x5c": []any{leafDER}},
	}
	return stmt, pool, challenge
}

func TestVerifyAtClock(t *testing.T) {
	t.Parallel()

	stmt, roots, challenge := expiredChain(t)
	inValidity := func() time.Time { return time.Date(2020, 2, 1, 0, 0, 0, 0, time.UTC) }

	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{name: "wall clock refuses an expired chain", wantErr: true},
		{name: "clock inside the chain's validity accepts it", opts: []Option{WithClock(inValidity)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := New(slog.New(slog.DiscardHandler), tt.opts...)
			v.trustedRoots = roots
			info, err := v.Verify(t.Context(), stmt, challenge)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && info.PermanentIdentifier.Identifier != "SERIAL" {
				t.Errorf("serial = %q, want SERIAL", info.PermanentIdentifier.Identifier)
			}
		})
	}
}
