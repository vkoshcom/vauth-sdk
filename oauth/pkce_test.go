package oauth_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/vkoshcom/vauth/oauth"
)

func TestGeneratePKCE(t *testing.T) {
	pkce, err := oauth.GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE failed: %v", err)
	}

	if pkce.Verifier == "" {
		t.Errorf("expected non-empty Verifier")
	}
	if pkce.Challenge == "" {
		t.Errorf("expected non-empty Challenge")
	}
	if pkce.Method != "S256" {
		t.Errorf("expected S256 method, got %q", pkce.Method)
	}
	if pkce.State == "" {
		t.Errorf("expected non-empty State")
	}

	// Verify that Challenge matches SHA-256 of Verifier
	h := sha256.Sum256([]byte(pkce.Verifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(h[:])
	if pkce.Challenge != expectedChallenge {
		t.Errorf("expected challenge %q, got %q", expectedChallenge, pkce.Challenge)
	}
}
