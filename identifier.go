package nanoca

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// validateIdentifier checks an order identifier value against the grammar
// in draft-ietf-acme-device-attest-10 Sections 3.1 and 4.1: a non-empty
// UTF-8 serial without "/", then an optional (permanent-identifier) or
// required (hardware-module) "/" and dotted-decimal OID.
func validateIdentifier(id Identifier) error {
	if !utf8.ValidString(id.Value) {
		return errors.New("identifier value is not valid UTF-8")
	}
	serial, oid, hasOID := strings.Cut(id.Value, "/")
	if serial == "" {
		return errors.New("identifier value has an empty serial")
	}
	switch id.Type {
	case IdentifierTypePermanentIdentifier:
		if !hasOID {
			return nil
		}
	case IdentifierTypeHardwareModule:
		if !hasOID {
			return errors.New("hardware-module value has no hardware type OID")
		}
	default:
		return fmt.Errorf("unsupported identifier type %q", id.Type)
	}
	// x509.ParseOID allows leading zeros, which the grammar forbids. The
	// round trip through String rejects them.
	if parsed, err := x509.ParseOID(oid); err != nil || parsed.String() != oid {
		return fmt.Errorf("invalid OID %q", oid)
	}
	return nil
}

// identifierValue returns the attested identity of the given type in the
// order-resource form of draft-ietf-acme-device-attest-10 Sections 3.1 and
// 4.1, or "" if the device has no identity of that type.
func (d *DeviceInfo) identifierValue(typ string) string {
	switch typ {
	case IdentifierTypePermanentIdentifier:
		if d.PermanentIdentifier == nil {
			return ""
		}
		if len(d.PermanentIdentifier.Assigner) == 0 {
			return d.PermanentIdentifier.Identifier
		}
		return d.PermanentIdentifier.Identifier + "/" + d.PermanentIdentifier.Assigner.String()
	case IdentifierTypeHardwareModule:
		if d.HardwareModule == nil {
			return ""
		}
		return string(d.HardwareModule.Value) + "/" + d.HardwareModule.Type.String()
	}
	return ""
}

// matches reports whether the attested identity is an octet-for-octet
// match for the order identifier (draft-ietf-acme-device-attest-10
// Section 5, step 3).
func (d *DeviceInfo) matches(id Identifier) bool {
	value := d.identifierValue(id.Type)
	return value != "" && value == id.Value
}
