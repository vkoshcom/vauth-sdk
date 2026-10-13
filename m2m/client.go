package m2m

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config configures the Machine-to-Machine client.
type Config struct {
	// TokenURL is the token endpoint (e.g. "https://auth.vkosh.com/oauth2/v1/token").
	TokenURL string

	// ClientID is the confidential client's ID.
	ClientID string

	// ClientSecret is the confidential client's secret.
	ClientSecret string

	// Scopes requested for the M2M token (optional).
	Scopes []string

	// HTTPClient is used to request tokens. Defaults to 10s timeout client.
	HTTPClient *http.Client
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// Client manages automated M2M access tokens with thread-safe caching and pre-expiry refresh.
type Client struct {
	cfg Config

	mu          sync.RWMutex
	accessToken string
	expiresAt   time.Time
}

// NewClient creates a new M2M token manager.
func NewClient(cfg Config) (*Client, error) {
	if cfg.TokenURL == "" {
		return nil, errors.New("m2m: TokenURL must be specified")
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("m2m: ClientID and ClientSecret must be specified")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &Client{cfg: cfg}, nil
}

// Token returns a valid access token, refreshing it automatically if expired or about to expire in 60s.
func (c *Client) Token(ctx context.Context) (string, error) {
	c.mu.RLock()
	// Refresh 60 seconds before token expiry
	if c.accessToken != "" && time.Now().Add(60*time.Second).Before(c.expiresAt) {
		token := c.accessToken
		c.mu.RUnlock()
		return token, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check inside lock
	if c.accessToken != "" && time.Now().Add(60*time.Second).Before(c.expiresAt) {
		return c.accessToken, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
	}
	if len(c.cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(c.cfg.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("m2m: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("m2m: token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("m2m: token request returned status %d: %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("m2m: failed to decode token response: %w", err)
	}

	c.accessToken = tr.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)

	return c.accessToken, nil
}
