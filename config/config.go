// Package config defines the configuration surface for chiauth.
package config

import (
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/kimenyu/chiauth/email"
	"github.com/kimenyu/chiauth/models"
)

// Config is the complete configuration for a chiauth instance.
// Pass it to chiauth.New() to mount the auth router.
type Config struct {
	// DB is the database connection. Required.
	DB *sqlx.DB

	// JWTSecret is the signing key for access tokens. Required.
	// Use a random string of at least 32 characters.
	JWTSecret string

	// JWTAccessTTL is how long access tokens live. Default: 15 minutes.
	JWTAccessTTL time.Duration

	// JWTRefreshTTL is how long refresh tokens live. Default: 7 days.
	JWTRefreshTTL time.Duration

	// PasswordMinLength sets the minimum password length. Default: 8.
	PasswordMinLength int

	// MaxLoginAttempts is the number of failed logins before lockout. Default: 5.
	MaxLoginAttempts int

	// RequireEmailVerify controls whether users must verify email before login.
	// Set to false for API-only apps or during development.
	// Default: true.
	RequireEmailVerify bool

	// AllowUsernameLogin allows login with username in addition to email.
	// Default: false.
	AllowUsernameLogin bool

	// AllowHardDelete enables permanent account deletion via DELETE /auth/me.
	// When false, accounts are soft-deleted (IsActive=false, DeletedAt set).
	// Default: false.
	AllowHardDelete bool

	// RotateRefreshTokens issues a new refresh token on every use and revokes the old one.
	// Recommended for production. Default: true.
	RotateRefreshTokens bool

	// BaseURL is used to construct links in emails (e.g. verification links).
	// Example: "https://api.yourapp.com"
	BaseURL string

	// AppName is used in email templates. Default: "chiauth".
	AppName string

	// SupportEmail is included in email footers. Optional.
	SupportEmail string

	// EmailSender is the implementation used to send auth emails.
	// If nil, tokens are printed to stdout (dev mode).
	EmailSender email.Sender

	// EmailTemplatesDir is an optional path to a directory containing
	// custom HTML templates that override the built-in defaults.
	// Files must be named: verification.html, password_reset.html, login_alert.html
	EmailTemplatesDir string

	// EmailTemplates allows inline HTML template overrides.
	// Takes priority over EmailTemplatesDir.
	EmailTemplates *EmailTemplateOverrides

	// Lifecycle Hooks 
	// Hooks fire after successful operations. Use them to integrate
	// with your own systems (CRM, analytics, Slack, etc.) without patching chiauth.

	// OnUserCreated fires after a new user is registered.
	OnUserCreated func(user *models.User)

	// OnUserActivated fires after a user verifies their email.
	OnUserActivated func(user *models.User)

	// OnLogin fires after a successful login.
	OnLogin func(user *models.User, ip string)

	// OnPasswordReset fires after a password reset is completed.
	OnPasswordReset func(user *models.User)

	// OnAccountLocked fires when an account is locked due to failed attempts.
	OnAccountLocked func(user *models.User)

	// OnAccountDeleted fires when an account is deleted.
	OnAccountDeleted func(user *models.User)
}

// EmailTemplateOverrides allows inline HTML template strings.
// {{.FirstName}}, {{.VerificationURL}}, {{.ResetURL}}, {{.AppName}}, {{.SupportEmail}}
// are available as template variables.
type EmailTemplateOverrides struct {
	Verification   string // override for verification.html
	PasswordReset  string // override for password_reset.html
	LoginAlert     string // override for login_alert.html
}

// WithDefaults returns a Config with all zero-value fields filled in with sensible defaults.
func (c Config) WithDefaults() Config {
	if c.JWTAccessTTL == 0 {
		c.JWTAccessTTL = 15 * time.Minute
	}
	if c.JWTRefreshTTL == 0 {
		c.JWTRefreshTTL = 7 * 24 * time.Hour
	}
	if c.PasswordMinLength == 0 {
		c.PasswordMinLength = 8
	}
	if c.MaxLoginAttempts == 0 {
		c.MaxLoginAttempts = 5
	}
	if c.AppName == "" {
		c.AppName = "chiauth"
	}
	// RequireEmailVerify defaults to true
	if !c.RequireEmailVerify {
		c.RequireEmailVerify = true
	}
	// RotateRefreshTokens defaults to true
	c.RotateRefreshTokens = true
	return c
}
