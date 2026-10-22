package abm

import (
	"crypto"
	"net/http"
	"time"
)

// Apple Business Manager API values for Config.
const (
	BusinessBaseURL  = "https://api-business.apple.com/v1"
	BusinessTokenURL = "https://account.apple.com/auth/oauth2/token" // #nosec G101 - This is a public OAuth2 endpoint URL, not credentials
	BusinessScope    = "business.api"
)

// assertionAudience is the aud claim Apple requires in the client
// assertion. It differs from the token URL the assertion is posted to.
const assertionAudience = "https://account.apple.com/auth/oauth2/v2/token"

// pageLimit is the largest page size the API allows.
const pageLimit = 1000

// Values of Device.Status.
const (
	DeviceStatusAssigned   = "ASSIGNED"
	DeviceStatusUnassigned = "UNASSIGNED"
)

// Device represents a device in the ABM organization
type Device struct {
	SerialNumber string `json:"serialNumber"`
	Model        string `json:"deviceModel"`

	// Status is DeviceStatusAssigned if the device is assigned to a
	// device management service, and DeviceStatusUnassigned otherwise.
	Status string `json:"status"`
}

// deviceData represents the JSON:API data wrapper for a device
type deviceData struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes struct {
		Device
		ReleasedFromOrgDateTime *time.Time `json:"releasedFromOrgDateTime"`
	} `json:"attributes"`
}

// resourceID is a JSON:API resource identifier, as returned by
// relationship endpoints. For devices the ID is the serial number.
type resourceID struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// page represents one page of a JSON:API collection response
type page[T any] struct {
	Data  []T `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

// ErrorResponse represents an error response from the ABM API
type ErrorResponse struct {
	Errors []Error `json:"errors"`
}

// Error describes one problem in an ErrorResponse.
type Error struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Code   string `json:"code"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// Config holds the configuration for the ABM API client
type Config struct {
	// BaseURL is the API root, such as BusinessBaseURL.
	BaseURL string

	// HTTPClient sends the token exchange and API requests. If nil,
	// http.DefaultClient is used.
	HTTPClient *http.Client

	Token TokenConfig
}

// TokenConfig holds the configuration for getting OAuth2 access tokens with
// a signed client assertion
type TokenConfig struct {
	// ClientID is the OAuth client identifier
	ClientID string

	// KeyID is the key identifier (kid) for the JWT header
	KeyID string

	// PrivateKey is the P-256 key the client assertion is signed with
	PrivateKey crypto.Signer

	// TokenURL is the OAuth2 token endpoint, such as BusinessTokenURL.
	TokenURL string

	// Scope is the OAuth2 scope to request, such as BusinessScope.
	Scope string
}
