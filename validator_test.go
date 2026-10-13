package vauth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vkoshcom/vauth"
)

func TestValidator_Validate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	kid := "test-key-1"

	// Mock JWKS Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]interface{}{
			"keys": []map[string]string{
				{
					"kty": "OKP",
					"crv": "Ed25519",
					"kid": kid,
					"x":   base64.RawURLEncoding.EncodeToString(pub),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	// Mint a valid Ed25519 JWT
	claims := vauth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "usr_12345",
			Issuer:    server.URL,
			Audience:  jwt.ClaimStrings{"app-frontend"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Email:         "alex@example.com",
		EmailVerified: true,
		Roles:         []string{"member", "admin"},
		Permissions:   []string{"posts:read", "posts:write"},
		TenantID:      "tenant_corp",
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid

	signedJWT, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// Initialize VAuth Validator
	validator, err := vauth.NewValidator(vauth.Config{
		BaseURL:  server.URL,
		Audience: "app-frontend",
		CacheTTL: 1 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to initialize validator: %v", err)
	}

	// Validate valid token
	ctx := context.Background()
	validatedClaims, err := validator.Validate(ctx, signedJWT)
	if err != nil {
		t.Fatalf("validation unexpectedly failed: %v", err)
	}

	if validatedClaims.Subject != "usr_12345" {
		t.Errorf("expected subject 'usr_12345', got %q", validatedClaims.Subject)
	}
	if !validatedClaims.HasRole("admin") {
		t.Errorf("expected HasRole('admin') to be true")
	}
	if !validatedClaims.HasPermission("posts:write") {
		t.Errorf("expected HasPermission('posts:write') to be true")
	}
	if validatedClaims.TenantID != "tenant_corp" {
		t.Errorf("expected tenant_corp, got %q", validatedClaims.TenantID)
	}

	// Test invalid token signature (tampered)
	_, err = validator.Validate(ctx, signedJWT+"corrupt")
	if err == nil {
		t.Errorf("expected error for corrupted token, got nil")
	}

	// Test audience mismatch
	strictValidator, _ := vauth.NewValidator(vauth.Config{
		BaseURL:  server.URL,
		Audience: "different-app",
	})
	_, err = strictValidator.Validate(ctx, signedJWT)
	if err == nil {
		t.Errorf("expected error for audience mismatch, got nil")
	}
}
