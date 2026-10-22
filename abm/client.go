package abm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ErrNotFound is returned when the requested resource does not exist.
var ErrNotFound = errors.New("not found")

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
	c := &Client{httpClient: &apiClient, baseURL: config.BaseURL}
	redirect := httpClient.CheckRedirect
	// Transport authorizes every request it sends, so a redirect off the
	// API host would carry the access token there.
	apiClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := c.checkSameAPI(req.URL.String()); err != nil {
			return err
		}
		if redirect != nil {
			return redirect(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return c, nil
}

// GetOrganizationDevices retrieves all devices in the ABM organization.
func (c *Client) GetOrganizationDevices(ctx context.Context) ([]Device, error) {
	data, err := getAll[deviceData](ctx, c, "/orgDevices")
	if err != nil {
		return nil, err
	}
	devices := make([]Device, 0, len(data))
	for _, d := range data {
		devices = append(devices, d.Attributes.Device)
	}
	return devices, nil
}

// GetMDMServerSerials retrieves the serial numbers of the devices assigned
// to the device management service with the given ID.
func (c *Client) GetMDMServerSerials(ctx context.Context, serverID string) ([]string, error) {
	data, err := getAll[resourceID](ctx, c, "/mdmServers/"+url.PathEscape(serverID)+"/relationships/devices")
	if err != nil {
		return nil, err
	}
	serials := make([]string, 0, len(data))
	for _, d := range data {
		serials = append(serials, d.ID)
	}
	return serials, nil
}

// GetDevice retrieves the device with the given serial number. It returns
// ErrNotFound if the device is not in the organization or has been released
// from it, or if the response holds no device.
func (c *Client) GetDevice(ctx context.Context, serial string) (Device, error) {
	var resp struct {
		Data deviceData `json:"data"`
	}
	if err := c.get(ctx, c.baseURL+"/orgDevices/"+url.PathEscape(serial), &resp); err != nil {
		return Device{}, err
	}
	if resp.Data.ID == "" || resp.Data.Attributes.ReleasedFromOrgDateTime != nil {
		return Device{}, ErrNotFound
	}
	return resp.Data.Attributes.Device, nil
}

// GetAssignedServerID returns the ID of the device management service the
// device with the given serial number is assigned to. It returns
// ErrNotFound if the device is unknown or not assigned.
func (c *Client) GetAssignedServerID(ctx context.Context, serial string) (string, error) {
	var resp struct {
		Data *resourceID `json:"data"`
	}
	if err := c.get(ctx, c.baseURL+"/orgDevices/"+url.PathEscape(serial)+"/relationships/assignedServer", &resp); err != nil {
		return "", err
	}
	if resp.Data == nil || resp.Data.ID == "" {
		return "", ErrNotFound
	}
	return resp.Data.ID, nil
}

// getAll fetches every page of a collection, starting at path under the
// base URL and following links.next.
func getAll[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var all []T
	next := c.baseURL + path + "?limit=" + strconv.Itoa(pageLimit)
	for next != "" {
		var p page[T]
		if err := c.get(ctx, next, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Data...)
		next = p.Links.Next
		if next != "" {
			if err := c.checkSameAPI(next); err != nil {
				return nil, err
			}
		}
	}
	return all, nil
}

// checkSameAPI rejects a next-page or redirect URL that does not point at
// the API host, so the bearer token is never sent anywhere else.
func (c *Client) checkSameAPI(next string) error {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}
	u, err := url.Parse(next)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != base.Scheme || u.Host != base.Host {
		return fmt.Errorf("URL %q is not on %s", next, base.Host)
	}
	return nil
}

func (c *Client) get(ctx context.Context, requestURL string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return fmt.Errorf("API request failed with status %d", resp.StatusCode)
		}

		reasons := make([]string, 0, len(errorResp.Errors))
		for _, e := range errorResp.Errors {
			reasons = append(reasons, e.Code+": "+e.Detail)
		}
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, strings.Join(reasons, "; "))
	}

	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}
