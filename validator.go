package vauth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwkKey represents a single key entry inside a JWK set JSON document.
type jwkKey struct {
	Kty string `json:"kty"` // "OKP"
	Crv string `json:"crv"` // "Ed25519"
	Kid string `json:"kid"`
	X   string `json:"x"` // base64url-encoded raw 32-byte public key
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

// Validator validates Ed25519 JWT tokens against VAuth's JWKS endpoint with local caching.
type Validator struct {
	cfg Config

	mu        sync.RWMutex
	keyCache  map[string]ed25519.PublicKey // kid -> public key
	fetchedAt time.Time
}

// NewValidator initializes a new token validator.
func NewValidator(cfg Config) (*Validator, error) {
	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &Validator{
		cfg:      cfg,
		keyCache: make(map[string]ed25519.PublicKey),
	}, nil
}

// Validate parses, cryptographically verifies, and extracts claims from a raw JWT string.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("vauth: token is empty")
	}

	// 1. Parse unverified first to extract the "kid" from header
	unverified, _, err := new(jwt.Parser).ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil, fmt.Errorf("vauth: malformed token: %w", err)
	}

	kid, ok := unverified.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, errors.New("vauth: token header missing 'kid'")
	}

	// 2. Resolve public key from cache or fetch remote JWKS
	pubKey, err := v.resolveKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("vauth: key resolution failed: %w", err)
	}

	// 3. Full parse and cryptographic verification
	claims := &Claims{}
	parsedToken, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("vauth: unexpected signing algorithm: %v", t.Header["alg"])
		}
		return pubKey, nil
	})

	if err != nil || !parsedToken.Valid {
		return nil, fmt.Errorf("vauth: token verification failed: %w", err)
	}

	// 4. Validate Issuer if configured
	if v.cfg.Issuer != "" && claims.Issuer != v.cfg.Issuer {
		return nil, fmt.Errorf("vauth: issuer mismatch: got %q, expected %q", claims.Issuer, v.cfg.Issuer)
	}

	// 5. Validate Audience if configured
	if v.cfg.Audience != "" {
		audValid := false
		for _, a := range claims.Audience {
			if a == v.cfg.Audience {
				audValid = true
				break
			}
		}
		if !audValid {
			return nil, fmt.Errorf("vauth: audience mismatch: %v does not contain %q", claims.Audience, v.cfg.Audience)
		}
	}

	return claims, nil
}

// resolveKey finds the key in memory; if missing or cache expired, refreshes from remote JWKS.
func (v *Validator) resolveKey(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	v.mu.RLock()
	key, found := v.keyCache[kid]
	stale := time.Since(v.fetchedAt) > v.cfg.CacheTTL
	v.mu.RUnlock()

	if found && !stale {
		return key, nil
	}

	// Lock for writing and re-check to avoid stampede
	v.mu.Lock()
	defer v.mu.Unlock()

	// Double check
	if key, found = v.keyCache[kid]; found && time.Since(v.fetchedAt) <= v.cfg.CacheTTL {
		return key, nil
	}

	if err := v.refreshJWKS(ctx); err != nil {
		// If refresh fails but we have the key in stale cache, fail open with stale key
		if found {
			return key, nil
		}
		return nil, err
	}

	key, found = v.keyCache[kid]
	if !found {
		return nil, fmt.Errorf("key id %q not found in JWKS", kid)
	}

	return key, nil
}

// refreshJWKS fetches the latest keys from the remote JWKS URL.
func (v *Validator) refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return fmt.Errorf("failed to build JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("JWKS request returned status %d: %s", resp.StatusCode, string(body))
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}

	newCache := make(map[string]ed25519.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue
		}
		rawPub, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			continue
		}
		if len(rawPub) != ed25519.PublicKeySize {
			continue
		}
		newCache[k.Kid] = ed25519.PublicKey(rawPub)
	}

	v.keyCache = newCache
	v.fetchedAt = time.Now()
	return nil
}
