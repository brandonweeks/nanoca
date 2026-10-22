package abm

import (
	"crypto"
	"net/http"
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

// Device represents a device in the ABM organization
type Device struct {
	SerialNumber string `json:"serialNumber"`
	Model        string `json:"deviceModel"`
}

// deviceData represents the JSON:API data wrapper for a device
type deviceData struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes Device `json:"attributes"`
}

// devicesResponse represents one page of the JSON:API response from the
// Get Organization Devices endpoint
type devicesResponse struct {
	Data  []deviceData `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

// ErrorResponse represents an error response from the ABM API
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
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
