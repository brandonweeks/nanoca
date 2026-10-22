package nanoca_test

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
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

// issuedOtherNames completes every challenge of an order with the
// appleshaped format, finalizes, and returns the otherName type OIDs in
// the issued certificate's SAN.
func issuedOtherNames(t *testing.T, ids ...acme.AuthzID) []asn1.ObjectIdentifier {
	t.Helper()

	ts, _ := newTestServer(t, testServerConfig{verifiers: []nanoca.AttestationVerifier{appleShapedVerifier{}}})
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
		if err := submitAttObj(t, client, authz.Challenges[0], attObjFor(t, "appleshaped")); err != nil {
			t.Fatalf("failed to satisfy challenge: %v", err)
		}
	}

	chain, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, newCSR(t), true)
	if err != nil {
		t.Fatalf("CreateOrderCert() error = %v", err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatalf("failed to parse issued certificate: %v", err)
	}
	san := certutil.FindExtension(leaf, certutil.OIDSubjectAltName)
	if san == nil {
		t.Fatal("issued certificate has no SubjectAltName")
	}
	names, err := certutil.ParseOtherNames(san.Value)
	if err != nil {
		t.Fatalf("ParseOtherNames() error = %v", err)
	}
	var oids []asn1.ObjectIdentifier
	for _, n := range names {
		oids = append(oids, n.TypeID)
	}
	return oids
}

// The certificate names exactly the identifiers the order asked for. A
// device that attests more identities than were ordered does not get the
// extra ones in its certificate.
func TestIssuedSANsMatchOrderIdentifiers(t *testing.T) {
	t.Parallel()

	serial := acme.AuthzID{Type: "permanent-identifier", Value: testDeviceSerial}
	udid := acme.AuthzID{Type: "hardware-module", Value: testDeviceUDID + "/" + testUDIDOID.String()}

	tests := []struct {
		name string
		ids  []acme.AuthzID
		want []asn1.ObjectIdentifier
	}{
		{"serial only", []acme.AuthzID{serial}, []asn1.ObjectIdentifier{certutil.OIDPermanentIdentifier}},
		{"udid only", []acme.AuthzID{udid}, []asn1.ObjectIdentifier{certutil.OIDHardwareModuleName}},
		{"both", []acme.AuthzID{serial, udid}, []asn1.ObjectIdentifier{certutil.OIDPermanentIdentifier, certutil.OIDHardwareModuleName}},
		{"repeated", []acme.AuthzID{serial, serial}, []asn1.ObjectIdentifier{certutil.OIDPermanentIdentifier}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := issuedOtherNames(t, tt.ids...)
			if len(got) != len(tt.want) {
				t.Fatalf("otherNames = %v, want %v", got, tt.want)
			}
			for i := range got {
				if !got[i].Equal(tt.want[i]) {
					t.Errorf("otherName[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
