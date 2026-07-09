package nanoca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// makeCert creates a certificate signed by parent (parent==nil/self for a
// self-signed cert) and returns its DER. It is a minimal fixture for chain
// presentation tests, not a realistic CA.
func makeCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	signParent, signKey := template, key
	if parent != nil {
		signParent, signKey = parent, parentKey
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signParent, &key.PublicKey, signKey)
	if err != nil {
		t.Fatalf("create cert %q: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert %q: %v", cn, err)
	}
	return der, cert, key
}

func TestCertificateServedChain(t *testing.T) {
	t.Parallel()

	rootDER, root, rootKey := makeCert(t, "Root", nil, nil)
	intermDER, _, _ := makeCert(t, "Intermediate", root, rootKey)
	leafDER, _, _ := makeCert(t, "Leaf", root, rootKey)

	tests := []struct {
		name  string
		chain [][]byte
		want  [][]byte
	}{
		{"no chain serves leaf only", nil, [][]byte{leafDER}},
		{"self-signed root omitted", [][]byte{rootDER}, [][]byte{leafDER}},
		{"non-self-signed trailing kept", [][]byte{intermDER}, [][]byte{leafDER, intermDER}},
		{"intermediate kept, root omitted", [][]byte{intermDER, rootDER}, [][]byte{leafDER, intermDER}},
		{"unparseable trailing entry kept", [][]byte{[]byte("not-a-cert")}, [][]byte{leafDER, []byte("not-a-cert")}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := &Certificate{Raw: leafDER, ChainRaw: tc.chain}
			got := cert.ServedChain()
			if len(got) != len(tc.want) {
				t.Fatalf("ServedChain() len = %d, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if !bytes.Equal(got[i], tc.want[i]) {
					t.Errorf("ServedChain()[%d] mismatch", i)
				}
			}
		})
	}
}

func TestIsSelfSignedDER(t *testing.T) {
	t.Parallel()

	rootDER, root, rootKey := makeCert(t, "Root", nil, nil)
	intermDER, _, _ := makeCert(t, "Intermediate", root, rootKey)

	if !isSelfSignedDER(rootDER) {
		t.Error("self-signed root should be detected as self-signed")
	}
	if isSelfSignedDER(intermDER) {
		t.Error("intermediate should not be detected as self-signed")
	}
	if isSelfSignedDER([]byte("not-a-cert")) {
		t.Error("unparseable DER should not be detected as self-signed")
	}
}

// Expiry presentation must not fight the reservation lease: a processing
// order with a live reservation is mid-finalize and presents as processing
// even past Expires, while a lapsed one reads ready first and then falls to
// invalid. Terminal states are left alone.
func TestOrderPresentExpired(t *testing.T) {
	t.Parallel()

	past := time.Now().Add(-time.Minute)
	present := func(o *Order) string {
		o.presentLapsed(time.Minute)
		o.presentExpired()
		return o.Status
	}

	live := &Order{Status: OrderStatusProcessing, Expires: &past, Reservation: &Reservation{Token: "t", ReservedAt: time.Now()}}
	if got := present(live); got != OrderStatusProcessing {
		t.Errorf("live processing order presents %q, want %q", got, OrderStatusProcessing)
	}

	lapsed := &Order{Status: OrderStatusProcessing, Expires: &past, Reservation: &Reservation{Token: "t", ReservedAt: time.Now().Add(-time.Hour)}}
	if got := present(lapsed); got != OrderStatusInvalid {
		t.Errorf("lapsed processing order presents %q, want %q", got, OrderStatusInvalid)
	}

	valid := &Order{Status: OrderStatusValid, Expires: &past}
	if got := present(valid); got != OrderStatusValid {
		t.Errorf("valid order presents %q, want %q", got, OrderStatusValid)
	}

	unexpired := &Order{Status: OrderStatusPending}
	if got := present(unexpired); got != OrderStatusPending {
		t.Errorf("order without expiry presents %q, want %q", got, OrderStatusPending)
	}
}

func TestAuthorizationPresentExpired(t *testing.T) {
	t.Parallel()

	past := time.Now().Add(-time.Minute)
	for _, status := range []string{AuthzStatusPending, AuthzStatusValid} {
		authz := &Authorization{Status: status, Expires: &past}
		authz.presentExpired()
		if authz.Status != AuthzStatusExpired {
			t.Errorf("expired %s authorization presents %q, want %q", status, authz.Status, AuthzStatusExpired)
		}
	}

	invalid := &Authorization{Status: AuthzStatusInvalid, Expires: &past}
	invalid.presentExpired()
	if invalid.Status != AuthzStatusInvalid {
		t.Errorf("invalid authorization presents %q, want %q", invalid.Status, AuthzStatusInvalid)
	}
}
