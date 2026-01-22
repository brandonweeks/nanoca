// Package stderr provides an issuance observer that logs certificate issuance events to stderr.
package stderr

import (
	"context"
	"log/slog"

	"github.com/brandonweeks/nanoca"
)

// Observer logs certificate issuance events to stderr.
type Observer struct {
	logger *slog.Logger
}

func New(logger *slog.Logger) *Observer {
	return &Observer{logger: logger}
}

func (o *Observer) OnIssuance(ctx context.Context, event *nanoca.IssuanceEvent) error {
	deviceID := "unknown"
	if event.DeviceInfo != nil && event.DeviceInfo.PermanentIdentifier != nil {
		deviceID = event.DeviceInfo.PermanentIdentifier.Identifier
	}

	o.logger.InfoContext(ctx, "Certificate issued for device",
		"device_id", deviceID,
		"serial_number", event.Certificate.SerialNumber)

	return nil
}
