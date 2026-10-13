package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// UserInfo represents standard and extended profile claims returned by VAuth /oauth2/v1/userinfo.
type UserInfo struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Roles         []string `json:"roles"`
	Permissions   []string `json:"permissions"`
	TenantID      string   `json:"tenant_id,omitempty"`

	// Profile fields
	DisplayName   string   `json:"display_name,omitempty"`
	GivenName     string   `json:"given_name,omitempty"`
	FamilyName    string   `json:"family_name,omitempty"`
	AvatarURL     string   `json:"avatar_url,omitempty"`
	Locale        string   `json:"locale,omitempty"`
	Timezone      string   `json:"timezone,omitempty"`
	PhoneNumber   string   `json:"phone_number,omitempty"`
	PhoneVerified bool     `json:"phone_verified,omitempty"`
}

// UserInfoClient fetches profile and identity data using valid user access tokens.
type UserInfoClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewUserInfoClient creates a new UserInfo API client.
func NewUserInfoClient(baseURL string, httpClient *http.Client) *UserInfoClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &UserInfoClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

// GetUserInfo retrieves claims and profile details for the given Bearer access token.
func (c *UserInfoClient) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if accessToken == "" {
		return nil, errors.New("vauth/client: accessToken must not be empty")
	}

	endpoint := fmt.Sprintf("%s/oauth2/v1/userinfo", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vauth/client: userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("vauth/client: userinfo returned %d: %s", resp.StatusCode, string(body))
	}

	var u UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("vauth/client: failed to decode userinfo: %w", err)
	}
	return &u, nil
}
