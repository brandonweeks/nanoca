package abm

import (
	"testing"
	"time"
)

func TestRetryDelay(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		header  string
		attempt int
		want    time.Duration
	}{
		{"0", 0, 0},
		{"30", 2, 30 * time.Second},
		{"Thu, 22 Oct 2026 12:00:10 GMT", 0, 10 * time.Second},
		{"Thu, 22 Oct 2026 11:59:00 GMT", 0, 0},
		{"", 0, time.Second},
		{"", 2, 4 * time.Second},
		{"-5", 1, 2 * time.Second},
		{"soon", 0, time.Second},
	} {
		if got := retryDelay(tt.header, tt.attempt, now); got != tt.want {
			t.Errorf("retryDelay(%q, %d) = %v, want %v", tt.header, tt.attempt, got, tt.want)
		}
	}

	if got := retryDelay("10000000000", 0, now); got <= maxRetryAfter {
		t.Errorf("retryDelay(10000000000) = %v, want over %v", got, maxRetryAfter)
	}
}
