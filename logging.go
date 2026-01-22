package nanoca

import (
	"context"
	"log/slog"
)

type contextKey int

const (
	orderIDKey contextKey = iota
	accountIDKey
)

func WithOrderID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, orderIDKey, id)
}

func WithAccountID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, accountIDKey, id)
}

type ContextHandler struct {
	inner slog.Handler
}

func NewContextHandler(inner slog.Handler) *ContextHandler {
	return &ContextHandler{inner: inner}
}

func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if id, ok := ctx.Value(orderIDKey).(string); ok && id != "" {
		r.AddAttrs(slog.String("order_id", id))
	}
	if id, ok := ctx.Value(accountIDKey).(string); ok && id != "" {
		r.AddAttrs(slog.String("account_id", id))
	}
	return h.inner.Handle(ctx, r)
}

func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return NewContextHandler(h.inner.WithAttrs(attrs))
}

func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return NewContextHandler(h.inner.WithGroup(name))
}
