package vauth

import (
	"context"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey struct{}

// ContextKey is the context key for storing and retrieving validated VAuth Claims.
var ContextKey = contextKey{}

// Claims represents the rich decoded and verified JWT payload issued by VAuth.
type Claims struct {
	jwt.RegisteredClaims

	Email          string   `json:"email,omitempty"`
	EmailVerified  bool     `json:"email_verified,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	Permissions    []string `json:"permissions,omitempty"`
	AdminRole      string   `json:"admin_role,omitempty"`
	ScopedClientID string   `json:"scoped_client_id,omitempty"`
	ClientID       string   `json:"client_id,omitempty"`
	TenantID       string   `json:"tenant_id,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
}

// UserID returns the subject of the token (the user's UUID or service ID).
func (c *Claims) UserID() string {
	return c.Subject
}

// IsServicePrincipal returns true if this token belongs to an M2M machine service.
func (c *Claims) IsServicePrincipal() bool {
	return strings.HasPrefix(c.Subject, "service:")
}

// HasRole checks if the claims contain the specified application role.
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the claims contain at least one of the specified roles.
func (c *Claims) HasAnyRole(roles ...string) bool {
	for _, expected := range roles {
		if c.HasRole(expected) {
			return true
		}
	}
	return false
}

// HasPermission checks if the claims contain the specified permission.
func (c *Claims) HasPermission(permission string) bool {
	for _, p := range c.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the claims contain at least one of the specified permissions.
func (c *Claims) HasAnyPermission(perms ...string) bool {
	for _, expected := range perms {
		if c.HasPermission(expected) {
			return true
		}
	}
	return false
}

// IsExpired checks whether the token has expired relative to current time.
func (c *Claims) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return c.ExpiresAt.Time.Before(time.Now())
}

// ContextWithClaims injects Claims into a context.Context.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, ContextKey, claims)
}

// ClaimsFromContext extracts *Claims from context.Context. Returns nil if not present.
func ClaimsFromContext(ctx context.Context) *Claims {
	if c, ok := ctx.Value(ContextKey).(*Claims); ok {
		return c
	}
	return nil
}

// UserIDFromContext is a convenience helper to extract the subject ID from context.
func UserIDFromContext(ctx context.Context) string {
	if c := ClaimsFromContext(ctx); c != nil {
		return c.Subject
	}
	return ""
}

// TenantIDFromContext is a convenience helper to extract tenant ID from context.
func TenantIDFromContext(ctx context.Context) string {
	if c := ClaimsFromContext(ctx); c != nil {
		return c.TenantID
	}
	return ""
}
