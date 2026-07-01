package apple_test

import (
	"log/slog"
	"testing"

	"github.com/brandonweeks/nanoca/verifiers/apple"
)

func TestFormat(t *testing.T) {
	t.Parallel()

	if got := apple.New(slog.New(slog.DiscardHandler)).Format(); got != "apple" {
		t.Errorf("Format() = %q, want apple", got)
	}
}
