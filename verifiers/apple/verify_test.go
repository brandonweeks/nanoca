package apple_test

import (
	"log/slog"
	"testing"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/verifiers/apple"
)

func TestVerifyRejectsBadStatements(t *testing.T) {
	t.Parallel()

	verifier := apple.New(slog.New(slog.DiscardHandler))

	tests := []struct {
		name string
		stmt nanoca.AttestationStatement
	}{
		{"format mismatch", nanoca.AttestationStatement{Format: "null"}},
		{"missing x5c", nanoca.AttestationStatement{Format: "apple", AttStmt: map[string]any{}}},
		{"x5c not array", nanoca.AttestationStatement{Format: "apple", AttStmt: map[string]any{"x5c": "nope"}}},
		{"x5c empty", nanoca.AttestationStatement{Format: "apple", AttStmt: map[string]any{"x5c": []any{}}}},
		{"x5c entry not bytes", nanoca.AttestationStatement{Format: "apple", AttStmt: map[string]any{"x5c": []any{123}}}},
		{"x5c entry not a cert", nanoca.AttestationStatement{Format: "apple", AttStmt: map[string]any{"x5c": []any{[]byte("garbage")}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := verifier.Verify(t.Context(), tt.stmt, []byte("challenge")); err == nil {
				t.Error("Verify() error = nil, want error")
			}
		})
	}
}
