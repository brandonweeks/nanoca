package certutil

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/brandonweeks/nanoca"
)

// OtherName represents a parsed otherName entry from a SubjectAltName extension.
type OtherName struct {
	TypeID asn1.ObjectIdentifier
	Value  []byte // DER-encoded value inside the [0] EXPLICIT wrapper
}

// FindExtension returns the first extension matching oid, or nil.
func FindExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) *pkix.Extension {
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(oid) {
			return &cert.Extensions[i]
		}
	}
	return nil
}

// ParseOtherNames parses a DER-encoded SubjectAltName value and returns all
// otherName entries (GeneralName tag [0]).
func ParseOtherNames(sanDER []byte) ([]OtherName, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(sanDER, &seq)
	if err != nil {
		return nil, fmt.Errorf("unmarshal SAN SEQUENCE: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after SAN SEQUENCE")
	}

	var result []OtherName
	inner := seq.Bytes
	for len(inner) > 0 {
		var gn asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &gn)
		if err != nil {
			return nil, fmt.Errorf("unmarshal GeneralName: %w", err)
		}

		if gn.Class == asn1.ClassContextSpecific && gn.Tag == 0 && gn.IsCompound {
			on, err := parseOtherNameContent(gn.Bytes)
			if err != nil {
				return nil, err
			}
			result = append(result, on)
		}
	}
	return result, nil
}

func parseOtherNameContent(content []byte) (OtherName, error) {
	var typeID asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(content, &typeID)
	if err != nil {
		return OtherName{}, fmt.Errorf("unmarshal otherName type-id: %w", err)
	}

	var explicitValue asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &explicitValue)
	if err != nil {
		return OtherName{}, fmt.Errorf("unmarshal otherName [0] EXPLICIT value: %w", err)
	}
	if len(rest) > 0 {
		return OtherName{}, errors.New("trailing data in otherName")
	}

	return OtherName{TypeID: typeID, Value: explicitValue.Bytes}, nil
}

// ParsePermanentIdentifier parses a DER-encoded PermanentIdentifier value
// (the content inside the otherName [0] EXPLICIT wrapper).
func ParsePermanentIdentifier(der []byte) (*nanoca.PermanentIdentifier, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return nil, fmt.Errorf("unmarshal PermanentIdentifier SEQUENCE: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after PermanentIdentifier SEQUENCE")
	}

	pi := &nanoca.PermanentIdentifier{}
	inner := seq.Bytes

	if len(inner) > 0 {
		// Peek at the next element to see if it's a UTF8String (identifier).
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(inner, &raw); err == nil && raw.Tag == asn1.TagUTF8String && raw.Class == asn1.ClassUniversal {
			pi.Identifier = string(raw.Bytes)
			inner, _ = asn1.Unmarshal(inner, &raw)
		}
	}

	if len(inner) > 0 {
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(inner, &oid); err != nil {
			return nil, fmt.Errorf("unmarshal assigner OID: %w", err)
		}
		pi.Assigner = oid
	}

	return pi, nil
}

// ParseHardwareModule parses a DER-encoded HardwareModuleName value
// (the content inside the otherName [0] EXPLICIT wrapper).
func ParseHardwareModule(der []byte) (*nanoca.HardwareModule, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return nil, fmt.Errorf("unmarshal HardwareModuleName SEQUENCE: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after HardwareModuleName SEQUENCE")
	}

	inner := seq.Bytes

	var hwType asn1.ObjectIdentifier
	inner, err = asn1.Unmarshal(inner, &hwType)
	if err != nil {
		return nil, fmt.Errorf("unmarshal hwType OID: %w", err)
	}

	var hwSerial []byte
	if _, err := asn1.Unmarshal(inner, &hwSerial); err != nil {
		return nil, fmt.Errorf("unmarshal hwSerialNum: %w", err)
	}

	return &nanoca.HardwareModule{Type: hwType, Value: hwSerial}, nil
}
