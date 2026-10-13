package vauth

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// Config configures the VAuth validator and client.
type Config struct {
	// BaseURL is the root URL of the VAuth service (e.g., "https://auth.vkosh.com").
	// If set, JWKSURL and Issuer default to BaseURL + "/.well-known/jwks.json" and BaseURL respectively.
	BaseURL string

	// JWKSURL is the full URL to the public JWKS endpoint.
	// Defaults to BaseURL + "/.well-known/jwks.json" if omitted.
	JWKSURL string

	// Issuer is compared against the JWT "iss" claim.
	// If omitted and BaseURL is provided, defaults to BaseURL.
	Issuer string

	// Audience is compared against the JWT "aud" claim (your application's ClientID).
	// Leave empty to skip audience validation.
	Audience string

	// CacheTTL controls how long JWKS public keys are cached before background/on-demand refresh.
	// Defaults to 5 minutes.
	CacheTTL time.Duration

	// HTTPClient is the HTTP client used to fetch remote JWKS keys and execute auth calls.
	// Defaults to an HTTP client with a 10-second timeout.
	HTTPClient *http.Client
}

// SetDefaults applies sensible defaults to the configuration.
func (c *Config) SetDefaults() {
	if c.BaseURL != "" {
		c.BaseURL = strings.TrimRight(c.BaseURL, "/")
		if c.JWKSURL == "" {
			c.JWKSURL = c.BaseURL + "/.well-known/jwks.json"
		}
		if c.Issuer == "" {
			c.Issuer = c.BaseURL
		}
	}

	if c.CacheTTL <= 0 {
		c.CacheTTL = 5 * time.Minute
	}

	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}
}

// Validate checks that required fields are present.
func (c *Config) Validate() error {
	if c.JWKSURL == "" && c.BaseURL == "" {
		return errors.New("vauth: either BaseURL or JWKSURL must be provided")
	}
	return nil
}
