package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/vkoshcom/vauth"
)

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func writeJSONError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{
		Error:            code,
		ErrorDescription: description,
	})
}

// RequireAuth validates the Bearer token in the Authorization header.
// On success, injects *vauth.Claims into request context.
// On failure, returns HTTP 401 Unauthorized with OAuth2 JSON error format.
func RequireAuth(val *vauth.Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Missing or invalid Authorization header")
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := val.Validate(r.Context(), token)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "invalid_token", err.Error())
				return
			}

			ctx := vauth.ContextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuth parses and verifies the Bearer token if present, injecting claims into context.
// If the token is missing or invalid, it still allows the request through with no claims in context.
func OptionalAuth(val *vauth.Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				if claims, err := val.Validate(r.Context(), token); err == nil {
					ctx := vauth.ContextWithClaims(r.Context(), claims)
					r = r.WithContext(ctx)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole ensures that the authenticated caller has the specified role.
// Must be used after RequireAuth.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := vauth.ClaimsFromContext(r.Context())
			if claims == nil || !claims.HasRole(role) {
				writeJSONError(w, http.StatusForbidden, "insufficient_role", "Required role is missing")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole ensures that the caller possesses at least one of the specified roles.
func RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := vauth.ClaimsFromContext(r.Context())
			if claims == nil || !claims.HasAnyRole(roles...) {
				writeJSONError(w, http.StatusForbidden, "insufficient_role", "Caller lacks required role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission ensures that the authenticated caller has the specified permission.
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := vauth.ClaimsFromContext(r.Context())
			if claims == nil || !claims.HasPermission(permission) {
				writeJSONError(w, http.StatusForbidden, "forbidden", "Insufficient permissions for this operation")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermission ensures that the authenticated caller has at least one of the permissions.
func RequireAnyPermission(perms ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := vauth.ClaimsFromContext(r.Context())
			if claims == nil || !claims.HasAnyPermission(perms...) {
				writeJSONError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
