package nanoca_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/brandonweeks/nanoca"
)

func TestContextHandler(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	h := nanoca.NewContextHandler(slog.NewJSONHandler(&buf, nil))

	if !h.Enabled(t.Context(), slog.LevelInfo) {
		t.Error("Enabled() = false, want true")
	}

	logger := slog.New(h.WithAttrs([]slog.Attr{slog.String("base", "attr")}).WithGroup("grp"))

	ctx := nanoca.WithAccountID(nanoca.WithOrderID(t.Context(), "order-123"), "acct-456")
	logger.InfoContext(ctx, "with ids")
	if out := buf.String(); !strings.Contains(out, "order-123") || !strings.Contains(out, "acct-456") {
		t.Errorf("log output = %q, want order_id and account_id", out)
	}

	buf.Reset()
	logger.InfoContext(t.Context(), "no ids")
	if out := buf.String(); strings.Contains(out, "order_id") || strings.Contains(out, "account_id") {
		t.Errorf("log output = %q, want no order_id/account_id", out)
	}
}
