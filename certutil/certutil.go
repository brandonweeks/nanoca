// Package certutil provides ASN.1/X.509 certificate extension utilities
// for building SubjectAltName extensions with PermanentIdentifier (RFC 4043)
// and HardwareModuleName (RFC 4108) otherName entries.
package certutil

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/brandonweeks/nanoca"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// OIDPermanentIdentifier is id-on-permanentIdentifier from RFC 4043.
	OIDPermanentIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}
	// OIDHardwareModuleName is id-on-hardwareModuleName from RFC 4108.
	OIDHardwareModuleName = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 4}
	// OIDSubjectAltName is the SubjectAltName extension OID.
	OIDSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// BuildSANExtension constructs a SubjectAltName extension containing otherName
// entries for PermanentIdentifier (RFC 4043) and HardwareModuleName (RFC 4108),
// plus any URI SANs from the CSR. Returns nil if there are no SANs to encode.
func BuildSANExtension(deviceInfos []*nanoca.DeviceInfo, csr *x509.CertificateRequest) (*pkix.Extension, error) {
	// Validate HardwareModuleName fields upfront, before building ASN.1.
	for _, di := range deviceInfos {
		if di.HardwareModule != nil && (len(di.HardwareModule.Type) == 0 || len(di.HardwareModule.Value) == 0) {
			return nil, errors.New("HardwareModuleName requires both hwType and hwSerialNum (RFC 4108)")
		}
	}

	var b cryptobyte.Builder
	var hasEntries bool
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, di := range deviceInfos {
			if di.PermanentIdentifier != nil {
				hasEntries = true
				AddPermanentIdentifierOtherName(b, di.PermanentIdentifier)
			}
			if di.HardwareModule != nil {
				hasEntries = true
				AddHardwareModuleOtherName(b, di.HardwareModule)
			}
		}
		for _, uri := range csr.URIs {
			hasEntries = true
			b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(uri.String()))
			})
		}
	})

	if !hasEntries {
		return nil, nil
	}

	sanValue, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding SubjectAltName: %w", err)
	}

	return &pkix.Extension{
		Id:       OIDSubjectAltName,
		Critical: false,
		Value:    sanValue,
	}, nil
}

// AddPermanentIdentifierOtherName appends a PermanentIdentifier (RFC 4043)
// otherName entry to the parent builder:
//
//	PermanentIdentifier ::= SEQUENCE {
//	    identifierValue  UTF8String        OPTIONAL,
//	    assigner         OBJECT IDENTIFIER OPTIONAL
//	}
func AddPermanentIdentifierOtherName(b *cryptobyte.Builder, pi *nanoca.PermanentIdentifier) {
	// otherName [0] IMPLICIT SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
	b.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(OIDPermanentIdentifier)
		b.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				if pi.Identifier != "" {
					b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(pi.Identifier))
					})
				}
				if len(pi.Assigner) > 0 {
					b.AddASN1ObjectIdentifier(pi.Assigner)
				}
			})
		})
	})
}

// AddHardwareModuleOtherName appends a HardwareModuleName (RFC 4108)
// otherName entry to the parent builder:
//
//	HardwareModuleName ::= SEQUENCE {
//	    hwType       OBJECT IDENTIFIER,
//	    hwSerialNum  OCTET STRING
//	}
func AddHardwareModuleOtherName(b *cryptobyte.Builder, hm *nanoca.HardwareModule) {
	b.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(OIDHardwareModuleName)
		b.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(hm.Type)
				b.AddASN1OctetString(hm.Value)
			})
		})
	})
}
