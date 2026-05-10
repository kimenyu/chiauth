// Package services contains all business logic for chiauth.
package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/kimenyu/chiauth/models"
	"github.com/kimenyu/chiauth/store"
)

// JWTClaims holds the payload of a chiauth access token.
type JWTClaims struct {
	UserID      uuid.UUID `json:"user_id"`
	Email       string    `json:"email"`
	IsStaff     bool      `json:"is_staff"`
	IsSuperuser bool      `json:"is_superuser"`
	Roles       []string  `json:"roles"` // role slugs only — keep payload small
	jwt.RegisteredClaims
}

// TokenService handles JWT and refresh token lifecycle.
type TokenService struct {
	secret        string
	accessTTL     time.Duration
	refreshTTL    time.Duration
	rotatetokens  bool
	tokenStore    store.TokenStore
}

// NewTokenService creates a TokenService.
func NewTokenService(
	secret string,
	accessTTL, refreshTTL time.Duration,
	rotateTokens bool,
	tokenStore store.TokenStore,
) *TokenService {
	return &TokenService{
		secret:       secret,
		accessTTL:    accessTTL,
		refreshTTL:   refreshTTL,
		rotatetokens: rotateTokens,
		tokenStore:   tokenStore,
	}
}

// GenerateAccessToken signs a short-lived JWT for the given user.
func (s *TokenService) GenerateAccessToken(user *models.User) (string, time.Time, error) {
	expiresAt := time.Now().Add(s.accessTTL)

	roleSlugs := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roleSlugs[i] = r.Slug
	}

	claims := JWTClaims{
		UserID:      user.ID,
		Email:       user.Email,
		IsStaff:     user.IsStaff,
		IsSuperuser: user.IsSuperuser,
		Roles:       roleSlugs,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(), // jti — unique per token
			Subject:   user.ID.String(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.secret))
	return signed, expiresAt, err
}

// ValidateAccessToken parses and validates a JWT string.
func (s *TokenService) ValidateAccessToken(tokenStr string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &JWTClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// IssueRefreshToken generates a cryptographically random refresh token,
// stores its hash in the database, and returns the raw token to the caller.
func (s *TokenService) IssueRefreshToken(ctx context.Context, user *models.User, r *http.Request) (string, error) {
	raw, hash, err := generateSecureToken()
	if err != nil {
		return "", err
	}

	rt := &models.RefreshToken{
		UserID:     user.ID,
		TokenHash:  hash,
		DeviceInfo: r.Header.Get("User-Agent"),
		IPAddress:  extractIP(r),
		UserAgent:  r.Header.Get("User-Agent"),
		ExpiresAt:  time.Now().Add(s.refreshTTL),
	}

	if err := s.tokenStore.SaveRefreshToken(ctx, rt); err != nil {
		return "", err
	}
	return raw, nil
}

// RotateRefreshToken revokes the presented token and issues a new one.
// If the presented token was already revoked, it revokes ALL tokens for the
// user — this indicates possible token theft.
func (s *TokenService) RotateRefreshToken(ctx context.Context, rawToken string, user *models.User, r *http.Request) (string, error) {
	hash := hashToken(rawToken)

	existing, err := s.tokenStore.GetRefreshToken(ctx, hash)
	if err != nil {
		return "", err
	}
	if existing == nil {
		return "", fmt.Errorf("refresh token not found")
	}
	if existing.RevokedAt != nil {
		// Token reuse detected — revoke everything for this user
		_ = s.tokenStore.RevokeAllUserTokens(ctx, user.ID)
		return "", fmt.Errorf("refresh token reuse detected — all sessions revoked")
	}
	if !existing.IsValid() {
		return "", fmt.Errorf("refresh token expired")
	}

	// Revoke old token
	if err := s.tokenStore.RevokeRefreshToken(ctx, hash); err != nil {
		return "", err
	}

	// Issue new token
	return s.IssueRefreshToken(ctx, user, r)
}

// RevokeRefreshToken invalidates a single refresh token.
func (s *TokenService) RevokeRefreshToken(ctx context.Context, rawToken string) error {
	return s.tokenStore.RevokeRefreshToken(ctx, hashToken(rawToken))
}

// RevokeAllUserTokens invalidates every session for a user.
func (s *TokenService) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	return s.tokenStore.RevokeAllUserTokens(ctx, userID)
}

// GetRefreshToken retrieves and validates a stored refresh token by raw value.
func (s *TokenService) GetRefreshToken(ctx context.Context, rawToken string) (*models.RefreshToken, error) {
	return s.tokenStore.GetRefreshToken(ctx, hashToken(rawToken))
}

// helpers

// generateSecureToken produces a cryptographically random 32-byte token.
// Returns (rawToken, sha256Hash, error).
func generateSecureToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw := base64.URLEncoding.EncodeToString(b)
	return raw, hashToken(raw), nil
}

// hashToken returns the hex-encoded SHA-256 hash of a raw token string.
func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h)
}

// extractIP returns the best-effort client IP from a request.
func extractIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
