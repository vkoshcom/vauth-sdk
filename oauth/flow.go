package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config configures the OAuth 2.0 / OIDC flow client.
type Config struct {
	BaseURL      string   // Root URL of VAuth (e.g., "https://auth.vkosh.com")
	ClientID     string   // Your application client_id
	ClientSecret string   // Optional: client_secret for confidential clients
	RedirectURI  string   // Callback redirect URI registered in VAuth
	Scopes       []string // Scopes (defaults to ["openid", "profile", "email"])
	HTTPClient   *http.Client
}

// TokenResponse represents the tokens returned upon code exchange or refresh.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Flow handles OAuth2 code exchange, token refresh, and session logout.
type Flow struct {
	cfg Config
}

// NewFlow creates an OAuth flow manager.
func NewFlow(cfg Config) (*Flow, error) {
	if cfg.BaseURL == "" || cfg.ClientID == "" || cfg.RedirectURI == "" {
		return nil, errors.New("oauth: BaseURL, ClientID, and RedirectURI are required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Flow{cfg: cfg}, nil
}

// AuthorizeURL generates the full redirect URL to initiate the login flow at VAuth.
func (f *Flow) AuthorizeURL(pkce *PKCE) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {f.cfg.ClientID},
		"redirect_uri":          {f.cfg.RedirectURI},
		"scope":                 {strings.Join(f.cfg.Scopes, " ")},
		"state":                 {pkce.State},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
	}
	return fmt.Sprintf("%s/oauth2/v1/authorize?%s", f.cfg.BaseURL, q.Encode())
}

// ExchangeCode trades an authorization code and PKCE code_verifier for tokens.
func (f *Flow) ExchangeCode(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	if code == "" || codeVerifier == "" {
		return nil, errors.New("oauth: code and codeVerifier must not be empty")
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {codeVerifier},
		"client_id":     {f.cfg.ClientID},
		"redirect_uri":  {f.cfg.RedirectURI},
	}
	if f.cfg.ClientSecret != "" {
		form.Set("client_secret", f.cfg.ClientSecret)
	}

	return f.doTokenRequest(ctx, form)
}

// RefreshToken obtains a new pair of access/refresh tokens using an existing refresh token.
func (f *Flow) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	if refreshToken == "" {
		return nil, errors.New("oauth: refreshToken must not be empty")
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {f.cfg.ClientID},
	}
	if f.cfg.ClientSecret != "" {
		form.Set("client_secret", f.cfg.ClientSecret)
	}

	return f.doTokenRequest(ctx, form)
}

// LogoutType specifies the scope of the logout action.
type LogoutType string

const (
	LogoutApp    LogoutType = "app"    // Revokes tokens for this app only; keeps SSO cookie active
	LogoutGlobal LogoutType = "global" // Revokes tokens and destroys global SSO session
)

// Logout revokes tokens and sessions at VAuth.
func (f *Flow) Logout(ctx context.Context, refreshToken string, logoutType LogoutType) error {
	form := url.Values{
		"refresh_token": {refreshToken},
		"client_id":     {f.cfg.ClientID},
		"logout_type":   {string(logoutType)},
	}

	endpoint := fmt.Sprintf("%s/oauth2/v1/logout", f.cfg.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("oauth: logout request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("oauth: logout failed (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

func (f *Flow) doTokenRequest(ctx context.Context, form url.Values) (*TokenResponse, error) {
	endpoint := fmt.Sprintf("%s/oauth2/v1/token", f.cfg.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if f.cfg.ClientSecret != "" {
		req.SetBasicAuth(f.cfg.ClientID, f.cfg.ClientSecret)
	}

	resp, err := f.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("oauth: token exchange failed (%d): %s", resp.StatusCode, string(body))
	}

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("oauth: failed to decode token response: %w", err)
	}
	return &tr, nil
}
