package certutil_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"testing"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/certutil"
)

func TestSANExtensionRoundTrip(t *testing.T) {
	t.Parallel()

	pi := &nanoca.PermanentIdentifier{
		Identifier: "SERIAL123",
		Assigner:   asn1.ObjectIdentifier{1, 2, 3, 4},
	}
	hm := &nanoca.HardwareModule{
		Type:  asn1.ObjectIdentifier{1, 2, 840, 113635, 100},
		Value: []byte{0xde, 0xad, 0xbe, 0xef},
	}
	uri, err := url.Parse("https://device.example/id")
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}
	devices := []*nanoca.DeviceInfo{{PermanentIdentifier: pi, HardwareModule: hm}}

	ext, err := certutil.BuildSANExtension(devices, &x509.CertificateRequest{URIs: []*url.URL{uri}})
	if err != nil {
		t.Fatalf("BuildSANExtension() error = %v", err)
	}
	if ext == nil {
		t.Fatal("BuildSANExtension() = nil, want extension")
	}

	cert := &x509.Certificate{Extensions: []pkix.Extension{*ext}}
	if certutil.FindExtension(cert, certutil.OIDSubjectAltName) == nil {
		t.Error("FindExtension(SAN) = nil, want extension")
	}
	if certutil.FindExtension(cert, certutil.OIDHardwareModuleName) != nil {
		t.Error("FindExtension(unrelated OID) != nil, want nil")
	}

	others, err := certutil.ParseOtherNames(ext.Value)
	if err != nil {
		t.Fatalf("ParseOtherNames() error = %v", err)
	}

	var sawPI, sawHM bool
	for _, on := range others {
		switch {
		case on.TypeID.Equal(certutil.OIDPermanentIdentifier):
			sawPI = true
			got, err := certutil.ParsePermanentIdentifier(on.Value)
			if err != nil {
				t.Fatalf("ParsePermanentIdentifier() error = %v", err)
			}
			if got.Identifier != pi.Identifier || !got.Assigner.Equal(pi.Assigner) {
				t.Errorf("PermanentIdentifier = %+v, want %+v", got, pi)
			}
		case on.TypeID.Equal(certutil.OIDHardwareModuleName):
			sawHM = true
			got, err := certutil.ParseHardwareModule(on.Value)
			if err != nil {
				t.Fatalf("ParseHardwareModule() error = %v", err)
			}
			if !got.Type.Equal(hm.Type) || !bytes.Equal(got.Value, hm.Value) {
				t.Errorf("HardwareModule = %+v, want %+v", got, hm)
			}
		}
	}
	if !sawPI || !sawHM {
		t.Errorf("otherNames missing entries: sawPI=%v sawHM=%v", sawPI, sawHM)
	}
}

func TestBuildSANExtensionEdgeCases(t *testing.T) {
	t.Parallel()

	ext, err := certutil.BuildSANExtension(nil, &x509.CertificateRequest{})
	if err != nil {
		t.Errorf("BuildSANExtension(empty) error = %v", err)
	}
	if ext != nil {
		t.Errorf("BuildSANExtension(empty) = %v, want nil", ext)
	}

	bad := []*nanoca.DeviceInfo{{HardwareModule: &nanoca.HardwareModule{}}}
	if _, err := certutil.BuildSANExtension(bad, &x509.CertificateRequest{}); err == nil {
		t.Error("BuildSANExtension(bad hardware module) error = nil, want error")
	}
}

func TestParseOtherNamesRejectsGarbage(t *testing.T) {
	t.Parallel()

	if _, err := certutil.ParseOtherNames([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Error("ParseOtherNames(garbage) error = nil, want error")
	}

	seq, err := asn1.Marshal(struct{ A int }{1})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := certutil.ParseOtherNames(append(seq, 0x00)); err == nil {
		t.Error("ParseOtherNames(trailing) error = nil, want error")
	}
}

func TestParseIdentifierErrors(t *testing.T) {
	t.Parallel()

	seqInt, err := asn1.Marshal(struct{ A int }{1}) // SEQUENCE { INTEGER }
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	oidThenInt, err := asn1.Marshal(struct {
		O asn1.ObjectIdentifier
		N int
	}{asn1.ObjectIdentifier{1, 2, 3}, 5}) // SEQUENCE { OID, INTEGER }
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	tests := []struct {
		name  string
		parse func() error
	}{
		{"permanent id not a sequence", func() error { _, e := certutil.ParsePermanentIdentifier([]byte{0xff, 0x01}); return e }},
		{"permanent id bad assigner", func() error { _, e := certutil.ParsePermanentIdentifier(seqInt); return e }},
		{"hardware module not a sequence", func() error { _, e := certutil.ParseHardwareModule([]byte{0xff, 0x01}); return e }},
		{"hardware module bad type", func() error { _, e := certutil.ParseHardwareModule(seqInt); return e }},
		{"hardware module bad serial", func() error { _, e := certutil.ParseHardwareModule(oidThenInt); return e }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.parse(); err == nil {
				t.Error("error = nil, want parse error")
			}
		})
	}
}
