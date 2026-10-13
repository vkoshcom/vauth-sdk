# VAuth Go SDK (`github.com/vkoshcom/vauth`)

Official Go SDK for seamless authentication and authorization with the **VAuth** identity service across the Vkosh ecosystem.

---

## Features

- **Ed25519 JWT Verification:** Thread-safe, auto-refreshing JWKS key caching with tolerance for 24h key rotation and 15min draining windows.
- **Rich Claims Support:** Out-of-the-box decoding of `Subject` (User ID), `Email`, `Roles`, `Permissions`, `TenantID`, `ClientID`, and `Scopes`.
- **HTTP Middlewares:** Drop-in middlewares for `net/http` and `chi` routers (`RequireAuth`, `OptionalAuth`, `RequireRole`, `RequirePermission`).
- **M2M Client Credentials Manager:** Proactive background token caching and auto-renewal before expiration for Machine-to-Machine communication.
- **Automated HTTP Transports:** Custom `http.RoundTripper` implementations that automatically attach `Bearer <token>` or `X-VAuth-Service-Key` to outbound requests.
- **OAuth 2.0 / PKCE Utilities:** RFC 7636 PKCE generator, authorization URL builder, code exchange, token refresh, and RP-initiated logout.
- **UserInfo & Profile Client:** Clean API to query user claims and profiles.

---

## Installation

```bash
go get github.com/vkoshcom/vauth
```

For local development within the Vkosh workspace, add to your `go.mod`:
```go
replace github.com/vkoshcom/vauth => ../vauth-sdk
```

---

## Quickstart

### 1. Protect HTTP APIs (Resource Server)

Use `vauth.NewValidator` and `middleware.RequireAuth` to protect your endpoints:

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vkoshcom/vauth"
	"github.com/vkoshcom/vauth/middleware"
)

func main() {
	// Initialize validator pointing to your VAuth service
	validator, err := vauth.NewValidator(vauth.Config{
		BaseURL:  "http://localhost:8080", // or "https://auth.yourco.com"
		Audience: "my-service",             // optional audience check
	})
	if err != nil {
		panic(err)
	}

	r := chi.NewRouter()

	// Public route
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth(validator))

		// Any authenticated user
		r.Get("/api/me", func(w http.ResponseWriter, r *http.Request) {
			claims := vauth.ClaimsFromContext(r.Context())
			fmt.Fprintf(w, "Hello User: %s (Tenant: %s)", claims.Subject, claims.TenantID)
		})

		// Restricted to "admin" role
		r.With(middleware.RequireRole("admin")).Get("/api/admin", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Welcome, Admin!"))
		})

		// Restricted to "posts:write" permission
		r.With(middleware.RequirePermission("posts:write")).Post("/api/posts", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Post created!"))
		})
	})

	http.ListenAndServe(":8090", r)
}
```

---

### 2. Machine-to-Machine (M2M) Calls

When one backend microservice needs to securely call another microservice:

```go
package main

import (
	"context"
	"fmt"
	"io"

	"github.com/vkoshcom/vauth/m2m"
)

func main() {
	// Initialize M2M Client Credentials manager
	client, err := m2m.NewClient(m2m.Config{
		TokenURL:     "http://localhost:8080/oauth2/v1/token",
		ClientID:     "service-billing",
		ClientSecret: "sec_xxxxxxxxxxxx",
	})
	if err != nil {
		panic(err)
	}

	// Option A: Obtain cached raw token (refreshes automatically 60s before expiry)
	token, err := client.Token(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println("Access Token:", token)

	// Option B: Wrap standard http.Client with automatic Bearer injection
	httpClient := m2m.NewBearerClient(client)
	resp, err := httpClient.Get("http://localhost:8091/api/data")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println("Response:", string(body))
}
```

---

### 3. Service Key Authentication (`X-VAuth-Service-Key`)

If your service consumes APIs authenticated via an environment service key:

```go
httpClient := m2m.NewServiceKeyClient("vauth_live_xxxxxxxxxxxx")
resp, err := httpClient.Get("http://localhost:8080/admin/clients")
```

---

### 4. Web Application / BFF (Authorization Code + PKCE)

If your Go application acts as a Backend-For-Frontend (BFF) or web application:

```go
package main

import (
	"net/http"

	"github.com/vkoshcom/vauth/oauth"
)

func main() {
	flow, err := oauth.NewFlow(oauth.Config{
		BaseURL:     "http://localhost:8080",
		ClientID:    "web-dashboard",
		RedirectURI: "http://localhost:3000/callback",
		Scopes:      []string{"openid", "profile", "email"},
	})
	if err != nil {
		panic(err)
	}

	// 1. Initiate Login
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		pkce, _ := oauth.GeneratePKCE()
		// Save pkce.Verifier in a secure, short-lived HttpOnly cookie
		http.Redirect(w, r, flow.AuthorizeURL(pkce), http.StatusFound)
	})

	// 2. Handle Callback
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		codeVerifier := "..." // Retrieve from cookie
		tokens, err := flow.ExchangeCode(r.Context(), code, codeVerifier)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// tokens.AccessToken, tokens.RefreshToken, tokens.IDToken
	})

	// 3. Logout
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		refreshToken := "..."
		_ = flow.Logout(r.Context(), refreshToken, oauth.LogoutApp)
	})
}
```

---

## Package Structure

```
vauth-sdk/
├── claims.go        # Decoded VAuth claims (*Claims) & Context helpers
├── config.go        # Configuration options and defaults
├── validator.go     # Thread-safe remote JWKS fetcher & Ed25519 verifier
├── middleware/
│   └── std.go       # net/http & Chi middlewares (RequireAuth, RequireRole, etc.)
├── m2m/
│   ├── client.go    # Client credentials token manager with auto-refresh
│   └── transport.go # http.RoundTripper injecting Bearer / ServiceKey
├── oauth/
│   ├── pkce.go      # RFC 7636 PKCE generator
│   └── flow.go      # Authorize URL, code exchange, refresh, and logout
└── client/
    └── userinfo.go  # UserInfo & Profile client
```
