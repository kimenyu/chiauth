// Package middleware provides Chi-compatible HTTP middleware for chiauth.
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/kimenyu/chiauth/models"
	"github.com/kimenyu/chiauth/services"
)

// contextKey is an unexported type for context keys to avoid collisions.
type contextKey string

const (
	// UserContextKey is the key under which the resolved *models.User is stored in context.
	UserContextKey contextKey = "chiauth_user"
	// ClaimsContextKey stores the raw JWT claims.
	ClaimsContextKey contextKey = "chiauth_claims"
)

// UserFromContext retrieves the authenticated user from the request context.
// Returns nil if the user is not present (i.e. Authenticate middleware was not applied).
func UserFromContext(ctx context.Context) *models.User {
	u, _ := ctx.Value(UserContextKey).(*models.User)
	return u
}

// ClaimsFromContext retrieves the JWT claims from the request context.
func ClaimsFromContext(ctx context.Context) *services.JWTClaims {
	c, _ := ctx.Value(ClaimsContextKey).(*services.JWTClaims)
	return c
}

// AuthMiddleware holds the dependencies needed by auth middleware functions.
type AuthMiddleware struct {
	tokenSvc  *services.TokenService
	userStore userGetter
}

// userGetter is a minimal interface so middleware doesn't depend on the full store package.
type userGetter interface {
	GetByID(ctx context.Context, id interface{}) (*models.User, error)
}

// NewAuthMiddleware creates an AuthMiddleware.
func NewAuthMiddleware(tokenSvc *services.TokenService) *AuthMiddleware {
	return &AuthMiddleware{tokenSvc: tokenSvc}
}

// AUTHENTICATE

// Authenticate validates the Bearer token and injects the *models.User into context.
// Returns 401 if the token is missing, malformed, or expired.
// The user's roles and permissions are loaded from the JWT claims (no DB hit).
//
// Usage:
//
//	r.With(mw.Authenticate).Get("/dashboard", handler)
func (m *AuthMiddleware) Authenticate(userStore interface {
	GetByID(ctx context.Context, id interface{}) (*models.User, error)
}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				jsonError(w, "missing or malformed Authorization header", http.StatusUnauthorized)
				return
			}

			claims, err := m.tokenSvc.ValidateAccessToken(token)
			if err != nil {
				jsonError(w, "invalid or expired access token", http.StatusUnauthorized)
				return
			}

			// Build a lightweight user from claims — avoids a DB round-trip on every request.
			// Full DB load is only needed for admin actions that check live permissions.
			user := &models.User{
				ID:          claims.UserID,
				Email:       claims.Email,
				IsStaff:     claims.IsStaff,
				IsSuperuser: claims.IsSuperuser,
				IsActive:    true,
			}
			// Reconstruct roles from slugs in claims
			roles := make([]models.Role, len(claims.Roles))
			for i, slug := range claims.Roles {
				roles[i] = models.Role{Slug: slug}
			}
			user.Roles = roles

			ctx := context.WithValue(r.Context(), UserContextKey, user)
			ctx = context.WithValue(ctx, ClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AuthenticateFull is like Authenticate but loads the full user from the DB,
// including live roles and direct permissions. Use on sensitive endpoints
// where you need up-to-date permission state.
func AuthenticateFull(tokenSvc *services.TokenService, getUser func(ctx context.Context, id interface{}) (*models.User, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				jsonError(w, "missing or malformed Authorization header", http.StatusUnauthorized)
				return
			}

			claims, err := tokenSvc.ValidateAccessToken(token)
			if err != nil {
				jsonError(w, "invalid or expired access token", http.StatusUnauthorized)
				return
			}

			user, err := getUser(r.Context(), claims.UserID)
			if err != nil || user == nil || !user.IsActive || user.IsLocked || user.DeletedAt != nil {
				jsonError(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, user)
			ctx = context.WithValue(ctx, ClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// REQUIRE ROLE

// RequireRole returns middleware that allows only users with the given role slug.
// Must be chained after Authenticate.
//
// Usage:
//
//	r.With(mw.Authenticate(...), RequireRole("admin")).Get("/admin", handler)
func RequireRole(slug string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				jsonError(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !user.HasAnyRole(slug) && !user.IsSuperuser {
				jsonError(w, "forbidden: insufficient role", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole allows users with at least one of the given role slugs.
//
// Usage:
//
//	r.With(mw.Authenticate(...), RequireAnyRole("admin", "staff"))
func RequireAnyRole(slugs ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				jsonError(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !user.HasAnyRole(slugs...) && !user.IsSuperuser {
				jsonError(w, "forbidden: insufficient role", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// REQUIRE PERMISSION

// RequirePermission returns middleware that gates on a specific permission codename.
// Must be chained after Authenticate.
//
// Usage:
//
//	r.With(mw.Authenticate(...), RequirePermission("invoice:delete")).Delete(...)
func RequirePermission(codename string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				jsonError(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !user.HasPermission(codename) {
				jsonError(w, "forbidden: missing permission "+codename, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// REQUIRE STAFF / SUPERUSER

// RequireStaff gates access to users with IsStaff=true or IsSuperuser=true.
func RequireStaff(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !user.IsStaff && !user.IsSuperuser {
			jsonError(w, "forbidden: staff access required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSuperuser gates access to superusers only.
func RequireSuperuser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !user.IsSuperuser {
			jsonError(w, "forbidden: superuser access required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HELPERS

func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(`{"error":"` + msg + `"}`)) //nolint:errcheck
}
