package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCE holds a generated PKCE verifier, challenge, and CSRF state parameter.
type PKCE struct {
	Verifier  string `json:"code_verifier"`
	Challenge string `json:"code_challenge"`
	Method    string `json:"code_challenge_method"` // "S256"
	State     string `json:"state"`
}

// GeneratePKCE generates a cryptographically secure random verifier (RFC 7636) and S256 challenge.
func GeneratePKCE() (*PKCE, error) {
	// Generate 64 bytes of random entropy for verifier
	verifierBytes := make([]byte, 64)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, fmt.Errorf("oauth/pkce: entropy generation failed: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Compute SHA-256 hash of the verifier
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Generate 32 bytes random state for CSRF protection
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("oauth/pkce: state generation failed: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	return &PKCE{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    "S256",
		State:     state,
	}, nil
}
