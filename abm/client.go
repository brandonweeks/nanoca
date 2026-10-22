package abm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// Client provides access to Apple Business Manager API
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// New creates a new ABM API client with the given configuration
func New(config *Config) (*Client, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}
	if config.BaseURL == "" {
		return nil, errors.New("base URL is required")
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	tokenSource, err := NewTokenSource(httpClient, config.Token)
	if err != nil {
		return nil, fmt.Errorf("token source setup failed: %w", err)
	}

	apiClient := *httpClient
	apiClient.Transport = &Transport{Source: tokenSource, Base: httpClient.Transport}
	return &Client{
		httpClient: &apiClient,
		baseURL:    config.BaseURL,
	}, nil
}

// GetOrganizationDevices retrieves all devices from the ABM organization.
// The API returns 100 devices per page with a links.next URL for the rest.
func (c *Client) GetOrganizationDevices(ctx context.Context) ([]Device, error) {
	var devices []Device
	next := c.baseURL + "/orgDevices"
	for next != "" {
		page, err := c.getDevicesPage(ctx, next)
		if err != nil {
			return nil, err
		}
		for _, deviceData := range page.Data {
			devices = append(devices, deviceData.Attributes)
		}
		next = page.Links.Next
		if next != "" {
			if err := c.checkSameAPI(next); err != nil {
				return nil, err
			}
		}
	}
	return devices, nil
}

// checkSameAPI rejects a next-page URL that does not point at the API
// host, so the bearer token is never sent anywhere else.
func (c *Client) checkSameAPI(next string) error {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}
	u, err := url.Parse(next)
	if err != nil {
		return fmt.Errorf("invalid next page URL: %w", err)
	}
	if u.Scheme != base.Scheme || u.Host != base.Host {
		return fmt.Errorf("next page URL %q is not on %s", next, base.Host)
	}
	return nil
}

func (c *Client) getDevicesPage(ctx context.Context, requestURL string) (*devicesResponse, error) {
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

	var page devicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &page, nil
}
