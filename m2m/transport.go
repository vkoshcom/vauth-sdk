package m2m

import (
	"fmt"
	"net/http"
)

// BearerTransport is an http.RoundTripper that automatically injects a valid M2M token.
type BearerTransport struct {
	Base   http.RoundTripper
	Client *Client
}

// RoundTrip executes a single HTTP transaction with the injected Bearer token.
func (t *BearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.Client.Token(req.Context())
	if err != nil {
		return nil, fmt.Errorf("vauth/m2m: failed to acquire token: %w", err)
	}

	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+token)

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}

// NewBearerClient wraps a standard http.Client with automatic M2M Bearer authentication.
func NewBearerClient(m2mClient *Client) *http.Client {
	return &http.Client{
		Transport: &BearerTransport{
			Client: m2mClient,
		},
	}
}

// ServiceKeyTransport is an http.RoundTripper that injects an X-VAuth-Service-Key header.
type ServiceKeyTransport struct {
	Base       http.RoundTripper
	ServiceKey string
}

// RoundTrip executes an HTTP transaction with the injected service key.
func (t *ServiceKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("X-VAuth-Service-Key", t.ServiceKey)

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}

// NewServiceKeyClient creates an http.Client that authenticates with an X-VAuth-Service-Key.
func NewServiceKeyClient(serviceKey string) *http.Client {
	return &http.Client{
		Transport: &ServiceKeyTransport{
			ServiceKey: serviceKey,
		},
	}
}
