package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// DomainCheckResult captures the diagnostic status of an email or domain.
type DomainCheckResult struct {
	Query       string   `json:"query"`
	Domain      string   `json:"domain"`
	Status      string   `json:"status"` // "blacklisted", "whitelisted", "clean_allowed"
	Source      string   `json:"source"`
	Reason      string   `json:"reason"`
	InBlocklist bool     `json:"in_blocklist"`
	InAllowlist bool     `json:"in_allowlist"`
	MXRecords   []string `json:"mx_records,omitempty"`
}

// CheckDisposableDomain checks with VAuth whether an email or domain is disposable or blacklisted.
func (c *UserInfoClient) CheckDisposableDomain(ctx context.Context, emailOrDomain string) (*DomainCheckResult, error) {
	if emailOrDomain == "" {
		return nil, errors.New("vauth/client: email or domain must not be empty")
	}

	endpoint := fmt.Sprintf("%s/admin/system/disposable-domains/check?query=%s", c.baseURL, url.QueryEscape(strings.TrimSpace(emailOrDomain)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vauth/client: domain check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if msg, ok := errResp["error"]; ok {
			return nil, fmt.Errorf("vauth/client: check returned error: %s", msg)
		}
		return nil, fmt.Errorf("vauth/client: check returned HTTP %d", resp.StatusCode)
	}

	var result DomainCheckResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("vauth/client: failed to decode check response: %w", err)
	}

	return &result, nil
}
