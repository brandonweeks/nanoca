package nanoca

import (
	"encoding/asn1"
	"testing"
)

func TestValidateIdentifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		typ, value string
		wantErr    bool
	}{
		{IdentifierTypePermanentIdentifier, "ABCDEF123456", false},
		{IdentifierTypePermanentIdentifier, "ABCDEF123456/1.2.3.4", false},
		{IdentifierTypePermanentIdentifier, "ABCDEF123456/2.999", false},
		{IdentifierTypePermanentIdentifier, "", true},
		{IdentifierTypePermanentIdentifier, "/1.2.3.4", true},
		{IdentifierTypePermanentIdentifier, "ABC/", true},
		{IdentifierTypePermanentIdentifier, "ABC/1", true},
		{IdentifierTypePermanentIdentifier, "ABC/1.40", true},
		{IdentifierTypePermanentIdentifier, "ABC/3.1", true},
		{IdentifierTypePermanentIdentifier, "ABC/1.02", true},
		{IdentifierTypePermanentIdentifier, "ABC/1.2/3", true},
		{IdentifierTypePermanentIdentifier, "ABC/1.2.a", true},
		{IdentifierTypePermanentIdentifier, "\xff", true},
		{IdentifierTypeHardwareModule, "ABCD/1.2.3.4", false},
		{IdentifierTypeHardwareModule, "00006030-000651690A84001C/1.2.840.113635.100.8.9.2", false},
		{IdentifierTypeHardwareModule, "ABCD", true},
		{IdentifierTypeHardwareModule, "ABCD/", true},
		{IdentifierTypeHardwareModule, "/1.2.3.4", true},
		{"dns", "device.example", true},
	}

	for _, tt := range tests {
		t.Run(tt.typ+" "+tt.value, func(t *testing.T) {
			t.Parallel()
			err := validateIdentifier(Identifier{Type: tt.typ, Value: tt.value})
			if (err != nil) != tt.wantErr {
				t.Errorf("validateIdentifier(%s %q) error = %v, wantErr %v", tt.typ, tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestDeviceInfoMatches(t *testing.T) {
	t.Parallel()

	udidOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 2}
	apple := &DeviceInfo{
		PermanentIdentifier: &PermanentIdentifier{Identifier: "TMWFWWWP67"},
		HardwareModule:      &HardwareModule{Type: udidOID, Value: []byte("00006030-000651690A84001C")},
	}
	assigned := &DeviceInfo{
		PermanentIdentifier: &PermanentIdentifier{Identifier: "ABC", Assigner: asn1.ObjectIdentifier{1, 2, 3, 4}},
	}

	tests := []struct {
		name   string
		device *DeviceInfo
		id     Identifier
		want   bool
	}{
		{"serial", apple, Identifier{Type: IdentifierTypePermanentIdentifier, Value: "TMWFWWWP67"}, true},
		{"serial case", apple, Identifier{Type: IdentifierTypePermanentIdentifier, Value: "tmwfwwwp67"}, false},
		{"serial with unexpected assigner", apple, Identifier{Type: IdentifierTypePermanentIdentifier, Value: "TMWFWWWP67/1.2.3.4"}, false},
		{"udid as permanent identifier", apple, Identifier{Type: IdentifierTypePermanentIdentifier, Value: "00006030-000651690A84001C"}, false},
		{"udid", apple, Identifier{Type: IdentifierTypeHardwareModule, Value: "00006030-000651690A84001C/1.2.840.113635.100.8.9.2"}, true},
		{"udid without type", apple, Identifier{Type: IdentifierTypeHardwareModule, Value: "00006030-000651690A84001C"}, false},
		{"udid wrong type", apple, Identifier{Type: IdentifierTypeHardwareModule, Value: "00006030-000651690A84001C/1.2.3.4"}, false},
		{"assigner", assigned, Identifier{Type: IdentifierTypePermanentIdentifier, Value: "ABC/1.2.3.4"}, true},
		{"assigner omitted", assigned, Identifier{Type: IdentifierTypePermanentIdentifier, Value: "ABC"}, false},
		{"no hardware module", assigned, Identifier{Type: IdentifierTypeHardwareModule, Value: "ABC/1.2.3.4"}, false},
		{"empty identity", &DeviceInfo{}, Identifier{Type: IdentifierTypePermanentIdentifier, Value: ""}, false},
		{"unknown type", apple, Identifier{Type: "dns", Value: "TMWFWWWP67"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.device.matches(tt.id); got != tt.want {
				t.Errorf("matches(%+v) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}
