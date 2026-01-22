package abm

import (
	"crypto"
)

// Apple Business Manager API constants
const (
	baseURL  = "https://api-business.apple.com/v1"
	tokenURL = "https://account.apple.com/auth/oauth2/token" // #nosec G101 - This is a public OAuth2 endpoint URL, not credentials
	scope    = "business.api"
)

// Device represents a device in the ABM organization
type Device struct {
	SerialNumber string `json:"serialNumber"`
	Model        string `json:"deviceModel"`
}

// deviceData represents the JSON:API data wrapper for a device (internal use)
type deviceData struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes Device `json:"attributes"`
}

// devicesResponse represents the JSON:API response from the Get Organization Devices endpoint (internal use)
type devicesResponse struct {
	Data []deviceData `json:"data"`
}

// ErrorResponse represents an error response from the ABM API
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Config holds the configuration for the ABM API client
type Config struct {
	// JWT configuration for Apple Business Manager API
	JWTConfig *JWTConfig
}

// JWTConfig holds configuration for JWT-based OAuth2 authentication
type JWTConfig struct {
	// ClientID is the OAuth client identifier
	ClientID string

	// PrivateKey is the private key for signing (e.g., *ecdsa.PrivateKey, *rsa.PrivateKey)
	PrivateKey crypto.Signer

	// KeyID is the key identifier (kid) for the JWT header
	KeyID string
}
