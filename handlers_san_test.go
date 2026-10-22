package nanoca_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/http/httptest"
	"testing"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/certutil"
	"golang.org/x/crypto/acme"
)

var testUDIDOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 2}

const testDeviceUDID = "00006030-000651690A84001C"

// appleShapedVerifier returns a serial and a UDID, like the Apple verifier.
type appleShapedVerifier struct{}

func (appleShapedVerifier) Format() string { return "appleshaped" }

func (appleShapedVerifier) Verify(context.Context, nanoca.AttestationStatement, []byte) (*nanoca.DeviceInfo, error) {
	return &nanoca.DeviceInfo{
		PermanentIdentifier: &nanoca.PermanentIdentifier{Identifier: testDeviceSerial},
		HardwareModule:      &nanoca.HardwareModule{Type: testUDIDOID, Value: []byte(testDeviceUDID)},
		PublicKey:           testDeviceKey.Public(),
	}, nil
}

// keyOnlyVerifier proves the key and no identity, like an Apple User
// Enrollment attestation.
type keyOnlyVerifier struct{}

func (keyOnlyVerifier) Format() string { return "keyonly" }

func (keyOnlyVerifier) Verify(context.Context, nanoca.AttestationStatement, []byte) (*nanoca.DeviceInfo, error) {
	return &nanoca.DeviceInfo{PublicKey: testDeviceKey.Public()}, nil
}

func newAppleShapedServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts, _ := newTestServer(t, testServerConfig{verifiers: []nanoca.AttestationVerifier{appleShapedVerifier{}}})
	return ts
}

// enroll orders ids, answers every challenge with attObj, finalizes with
// csr, and returns the issued leaf.
func enroll(t *testing.T, ts *httptest.Server, attObj string, csr []byte, ids ...acme.AuthzID) *x509.Certificate {
	t.Helper()

	client := newACMEClient(t, ts)
	order, err := client.AuthorizeOrder(t.Context(), ids)
	if err != nil {
		t.Fatalf("AuthorizeOrder() error = %v", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(t.Context(), authzURL)
		if err != nil {
			t.Fatalf("GetAuthorization() error = %v", err)
		}
		if err := submitAttObj(t, client, authz.Challenges[0], attObj); err != nil {
			t.Fatalf("failed to satisfy challenge: %v", err)
		}
	}

	chain, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, csr, true)
	if err != nil {
		t.Fatalf("CreateOrderCert() error = %v", err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatalf("failed to parse issued certificate: %v", err)
	}
	return leaf
}

func otherNames(t *testing.T, leaf *x509.Certificate) []certutil.OtherName {
	t.Helper()
	san := certutil.FindExtension(leaf, certutil.OIDSubjectAltName)
	if san == nil {
		t.Fatal("issued certificate has no SubjectAltName")
	}
	names, err := certutil.ParseOtherNames(san.Value)
	if err != nil {
		t.Fatalf("ParseOtherNames() error = %v", err)
	}
	return names
}

// wantNames checks that the SAN's otherNames are exactly want, that each
// one carries the attested value, and that claimed appears nowhere in it.
func wantNames(t *testing.T, leaf *x509.Certificate, claimed string, want ...asn1.ObjectIdentifier) {
	t.Helper()
	names := otherNames(t, leaf)
	if len(names) != len(want) {
		t.Fatalf("got %d otherNames, want %d", len(names), len(want))
	}
	for i := 0; i < len(names) && i < len(want); i++ {
		name := names[i]
		switch {
		case !name.TypeID.Equal(want[i]):
			t.Errorf("otherName[%d] = %v, want %v", i, name.TypeID, want[i])
		case name.TypeID.Equal(certutil.OIDPermanentIdentifier):
			pi, err := certutil.ParsePermanentIdentifier(name.Value)
			if err != nil {
				t.Fatalf("ParsePermanentIdentifier() error = %v", err)
			}
			if pi.Identifier != testDeviceSerial {
				t.Errorf("PermanentIdentifier = %q, want %q", pi.Identifier, testDeviceSerial)
			}
		case name.TypeID.Equal(certutil.OIDHardwareModuleName):
			hm, err := certutil.ParseHardwareModule(name.Value)
			if err != nil {
				t.Fatalf("ParseHardwareModule() error = %v", err)
			}
			if !hm.Type.Equal(testUDIDOID) || string(hm.Value) != testDeviceUDID {
				t.Errorf("HardwareModuleName = %v %q, want %v %q", hm.Type, hm.Value, testUDIDOID, testDeviceUDID)
			}
		}
	}
	if bytes.Contains(certutil.FindExtension(leaf, certutil.OIDSubjectAltName).Value, []byte(claimed)) {
		t.Errorf("SAN contains the order value %q", claimed)
	}
}

// The certificate names every identity the attestation proved, whatever
// identifier types the order used. Apple's client only ever orders a
// permanent-identifier and its certificates must still carry the UDID.
func TestIssuedSANsCarryAttestedIdentities(t *testing.T) {
	t.Parallel()

	serial := acme.AuthzID{Type: "permanent-identifier", Value: testDeviceSerial}
	label := acme.AuthzID{Type: "permanent-identifier", Value: "com.example.acme"}
	udid := acme.AuthzID{Type: "hardware-module", Value: testDeviceUDID + "/" + testUDIDOID.String()}

	tests := []struct {
		name string
		ids  []acme.AuthzID
	}{
		{"serial only", []acme.AuthzID{serial}},
		{"udid only", []acme.AuthzID{udid}},
		{"both", []acme.AuthzID{serial, udid}},
		{"same type twice", []acme.AuthzID{serial, label}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			leaf := enroll(t, newAppleShapedServer(t), attObjFor(t, "appleshaped"), newCSR(t), tt.ids...)
			wantNames(t, leaf, "com.example.acme", certutil.OIDPermanentIdentifier, certutil.OIDHardwareModuleName)
		})
	}
}

// Apple's ACME client sends the payload's ClientIdentifier as the
// permanent-identifier value. It is an opaque string, so it is not checked
// against the attestation and never appears in the certificate, which
// names the attested serial and UDID instead.
func TestOpaqueIdentifierValue(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"com.apple.oz.e2w.acme", "com.apple.oz/acme", "TEST"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			leaf := enroll(t, newAppleShapedServer(t), attObjFor(t, "appleshaped"), newCSR(t), acme.AuthzID{Type: "permanent-identifier", Value: value})
			wantNames(t, leaf, value, certutil.OIDPermanentIdentifier, certutil.OIDHardwareModuleName)
		})
	}
}

// A device cannot get a certificate for an identity it did not attest. It
// can claim another serial in the order and in the CSR's SAN, but the
// certificate still names only the attested serial.
func TestCertificateNamesOnlyAttestedIdentity(t *testing.T) {
	t.Parallel()

	const claimed = "other-device"
	claimedSAN, err := certutil.BuildSANExtension([]*nanoca.DeviceInfo{{PermanentIdentifier: &nanoca.PermanentIdentifier{Identifier: claimed}}}, &x509.CertificateRequest{})
	if err != nil {
		t.Fatalf("BuildSANExtension() error = %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "device"},
		ExtraExtensions: []pkix.Extension{*claimedSAN},
	}, testDeviceKey)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}

	ts, _ := newTestServer(t, testServerConfig{})
	leaf := enroll(t, ts, nullAttObj(t), csr, acme.AuthzID{Type: "permanent-identifier", Value: claimed})
	wantNames(t, leaf, claimed, certutil.OIDPermanentIdentifier)
}

// An attestation that proves only the key is left to the authorizer. With
// one that admits it, the certificate is bound to the attested key and
// names no device.
func TestAnonymousAttestationNamesNoDevice(t *testing.T) {
	t.Parallel()

	ts, _ := newTestServer(t, testServerConfig{verifiers: []nanoca.AttestationVerifier{keyOnlyVerifier{}}})
	leaf := enroll(t, ts, attObjFor(t, "keyonly"), newCSR(t), acme.AuthzID{Type: "permanent-identifier", Value: "com.apple.oz.e2w.acme"})
	if san := certutil.FindExtension(leaf, certutil.OIDSubjectAltName); san != nil {
		t.Errorf("issued certificate has a SubjectAltName %x, want none", san.Value)
	}
	if !testDeviceKey.PublicKey.Equal(leaf.PublicKey) {
		t.Error("issued certificate does not carry the attested key")
	}
}
