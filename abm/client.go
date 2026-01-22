package abm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Client provides access to Apple Business Manager API
type Client struct {
	config     *Config
	httpClient *http.Client
}

// New creates a new ABM API client with the given configuration
func New(ctx context.Context, config *Config) (*Client, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	if config.JWTConfig == nil {
		return nil, errors.New("JWT configuration is required for Apple Business Manager API")
	}

	httpClient, err := CreateJWTClient(ctx, config.JWTConfig)
	if err != nil {
		return nil, fmt.Errorf("JWT authentication setup failed: %w", err)
	}

	return &Client{
		config:     config,
		httpClient: httpClient,
	}, nil
}

// GetOrganizationDevices retrieves devices from the ABM organization
func (c *Client) GetOrganizationDevices(ctx context.Context) ([]Device, error) {
	requestURL := fmt.Sprintf("%s/orgDevices", baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
		}

		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, errorResp.Error)
	}

	var devicesResp devicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&devicesResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	devices := make([]Device, len(devicesResp.Data))
	for i, deviceData := range devicesResp.Data {
		devices[i] = deviceData.Attributes
	}

	return devices, nil
}
