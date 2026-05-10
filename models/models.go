// Package models defines all database models, DTOs, and domain types for chiauth.
package models

import (
	"time"

	"github.com/google/uuid"
)

// PERMISSION

// Permission is the atomic unit of access control.
// Resource + Action form the Codename: "invoice:delete".
// The consuming application seeds permissions; chiauth never defines them.
type Permission struct {
	ID          uuid.UUID `db:"id"          json:"id"`
	Codename    string    `db:"codename"    json:"codename"`    // "invoice:delete"
	Resource    string    `db:"resource"    json:"resource"`    // "invoice"
	Action      string    `db:"action"      json:"action"`      // "delete"
	Description string    `db:"description" json:"description"` // human-readable label
	CreatedAt   time.Time `db:"created_at"  json:"created_at"`
}

// ROLE

// Role is a named bundle of permissions.
// Users are assigned roles; roles carry permissions.
//
// System roles seeded automatically:
//   - slug:"superuser" — bypasses all permission checks
//   - slug:"staff"     — can access /auth/admin/* endpoints
//   - slug:"user"      — default role assigned on registration
type Role struct {
	ID          uuid.UUID    `db:"id"          json:"id"`
	Name        string       `db:"name"        json:"name"`
	Slug        string       `db:"slug"        json:"slug"`
	Description string       `db:"description" json:"description"`
	IsDefault   bool         `db:"is_default"  json:"is_default"` // auto-assigned on register
	IsSystem    bool         `db:"is_system"   json:"is_system"`  // cannot be deleted
	Permissions []Permission `db:"-"           json:"permissions,omitempty"`
	CreatedAt   time.Time    `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time    `db:"updated_at"  json:"updated_at"`
}

// RolePermission is the join table linking roles to permissions.
type RolePermission struct {
	RoleID       uuid.UUID `db:"role_id"`
	PermissionID uuid.UUID `db:"permission_id"`
	CreatedAt    time.Time `db:"created_at"`
}

// USER

// User is the central identity model.
//
// Permission resolution order (first match wins):
//  1. IsSuperuser → always granted
//  2. User.Permissions → direct grants
//  3. User.Roles → inherited via role membership
type User struct {
	ID           uuid.UUID  `db:"id"                    json:"id"`
	Email        string     `db:"email"                 json:"email"`
	Username     string     `db:"username"              json:"username,omitempty"`
	PasswordHash string     `db:"password_hash"         json:"-"` // never serialized
	FirstName    string     `db:"first_name"            json:"first_name"`
	LastName     string     `db:"last_name"             json:"last_name"`
	PhoneNumber  string     `db:"phone_number"          json:"phone_number,omitempty"`
	AvatarURL    string     `db:"avatar_url"            json:"avatar_url,omitempty"`

	// Access control flags
	IsActive    bool `db:"is_active"    json:"is_active"`    // false until email verified
	IsStaff     bool `db:"is_staff"     json:"is_staff"`     // can access admin endpoints
	IsSuperuser bool `db:"is_superuser" json:"is_superuser"` // bypasses all permission checks
	IsLocked    bool `db:"is_locked"    json:"is_locked"`    // locked after failed attempts

	// Populated by store, not DB columns
	Roles       []Role       `db:"-" json:"roles,omitempty"`
	Permissions []Permission `db:"-" json:"permissions,omitempty"`

	// Security tracking
	FailedLoginAttempts int        `db:"failed_login_attempts" json:"-"`
	LastLogin           *time.Time `db:"last_login"            json:"last_login,omitempty"`
	LastLoginIP         string     `db:"last_login_ip"         json:"-"`

	CreatedAt time.Time  `db:"created_at"  json:"created_at"`
	UpdatedAt time.Time  `db:"updated_at"  json:"updated_at"`
	DeletedAt *time.Time `db:"deleted_at"  json:"deleted_at,omitempty"` // soft delete
}

// HasPermission checks if the user holds a permission codename,
// either directly or through any of their roles.
// Superusers always return true.
func (u *User) HasPermission(codename string) bool {
	if u.IsSuperuser {
		return true
	}
	for _, p := range u.Permissions {
		if p.Codename == codename {
			return true
		}
	}
	for _, r := range u.Roles {
		for _, p := range r.Permissions {
			if p.Codename == codename {
				return true
			}
		}
	}
	return false
}

// HasRole returns true if the user holds a role with the given slug.
func (u *User) HasRole(slug string) bool {
	for _, r := range u.Roles {
		if r.Slug == slug {
			return true
		}
	}
	return false
}

// HasAnyRole returns true if the user holds at least one of the given slugs.
func (u *User) HasAnyRole(slugs ...string) bool {
	for _, slug := range slugs {
		if u.HasRole(slug) {
			return true
		}
	}
	return false
}

// DisplayName returns the best available human-readable name.
func (u *User) DisplayName() string {
	if u.FirstName != "" {
		return u.FirstName + " " + u.LastName
	}
	if u.Username != "" {
		return u.Username
	}
	return u.Email
}

// ToResponse converts the User to its safe API response shape.
func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:          u.ID,
		Email:       u.Email,
		Username:    u.Username,
		FirstName:   u.FirstName,
		LastName:    u.LastName,
		PhoneNumber: u.PhoneNumber,
		AvatarURL:   u.AvatarURL,
		IsActive:    u.IsActive,
		IsStaff:     u.IsStaff,
		IsSuperuser: u.IsSuperuser,
		Roles:       u.Roles,
		Permissions: u.Permissions,
		LastLogin:   u.LastLogin,
		CreatedAt:   u.CreatedAt,
	}
}

// UserRole is the join table linking users to roles.
type UserRole struct {
	UserID    uuid.UUID `db:"user_id"`
	RoleID    uuid.UUID `db:"role_id"`
	CreatedAt time.Time `db:"created_at"`
}

// UserPermission is a direct permission grant on a user, bypassing roles.
// Used for one-off access overrides.
type UserPermission struct {
	UserID       uuid.UUID `db:"user_id"`
	PermissionID uuid.UUID `db:"permission_id"`
	GrantedBy    uuid.UUID `db:"granted_by"` // ID of the admin who granted it
	CreatedAt    time.Time `db:"created_at"`
}

// ─────────────────────────────────────────────
// TOKENS
// ─────────────────────────────────────────────

// RefreshToken is a long-lived server-side session token.
// The raw token value is NEVER stored — only its SHA-256 hash.
type RefreshToken struct {
	ID         uuid.UUID  `db:"id"          json:"id"`
	UserID     uuid.UUID  `db:"user_id"     json:"user_id"`
	TokenHash  string     `db:"token_hash"  json:"-"`
	DeviceInfo string     `db:"device_info" json:"device_info,omitempty"`
	IPAddress  string     `db:"ip_address"  json:"ip_address,omitempty"`
	UserAgent  string     `db:"user_agent"  json:"-"`
	ExpiresAt  time.Time  `db:"expires_at"  json:"expires_at"`
	RevokedAt  *time.Time `db:"revoked_at"  json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `db:"created_at"  json:"created_at"`
}

// IsValid returns true if the token is not expired and not revoked.
func (t *RefreshToken) IsValid() bool {
	return t.RevokedAt == nil && time.Now().Before(t.ExpiresAt)
}

// OTPPurpose discriminates the use of a one-time token.
type OTPPurpose string

const (
	OTPPurposeEmailVerification OTPPurpose = "email_verification"
	OTPPurposePasswordReset     OTPPurpose = "password_reset"
	OTPPurposeTwoFactor         OTPPurpose = "two_factor"
	OTPPurposePhoneVerification OTPPurpose = "phone_verification"
)

// OTPToken is a short-lived, single-use token for out-of-band verification.
// All purposes share one table — Purpose discriminates.
// Raw tokens are never stored; only their SHA-256 hash.
type OTPToken struct {
	ID        uuid.UUID  `db:"id"         json:"id"`
	UserID    uuid.UUID  `db:"user_id"    json:"user_id"`
	TokenHash string     `db:"token_hash" json:"-"`
	Purpose   OTPPurpose `db:"purpose"    json:"purpose"`
	ExpiresAt time.Time  `db:"expires_at" json:"expires_at"`
	UsedAt    *time.Time `db:"used_at"    json:"used_at,omitempty"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
}

// IsValid returns true if the token has not been used and is not expired.
func (o *OTPToken) IsValid() bool {
	return o.UsedAt == nil && time.Now().Before(o.ExpiresAt)
}

// AUDIT LOG

// AuthEvent is a named auth lifecycle event recorded in the audit log.
type AuthEvent string

const (
	EventRegister          AuthEvent = "register"
	EventEmailVerified     AuthEvent = "email_verified"
	EventLoginSuccess      AuthEvent = "login_success"
	EventLoginFailed       AuthEvent = "login_failed"
	EventLogout            AuthEvent = "logout"
	EventLogoutAll         AuthEvent = "logout_all"
	EventTokenRefresh      AuthEvent = "token_refresh"
	EventPasswordChanged   AuthEvent = "password_changed"
	EventPasswordResetReq  AuthEvent = "password_reset_requested"
	EventPasswordResetDone AuthEvent = "password_reset_completed"
	EventAccountLocked     AuthEvent = "account_locked"
	EventAccountUnlocked   AuthEvent = "account_unlocked"
	EventRoleAssigned      AuthEvent = "role_assigned"
	EventRoleRevoked       AuthEvent = "role_revoked"
	EventPermissionGranted AuthEvent = "permission_granted"
	EventPermissionRevoked AuthEvent = "permission_revoked"
	EventProfileUpdated    AuthEvent = "profile_updated"
	EventAccountDeleted    AuthEvent = "account_deleted"
)

// AuditLog records every significant auth event.
// UserID is nullable because failed logins may not resolve to a valid user.
type AuditLog struct {
	ID        uuid.UUID         `db:"id"         json:"id"`
	UserID    *uuid.UUID        `db:"user_id"    json:"user_id,omitempty"`
	Event     AuthEvent         `db:"event"      json:"event"`
	IPAddress string            `db:"ip_address" json:"ip_address"`
	UserAgent string            `db:"user_agent" json:"user_agent"`
	Metadata  map[string]string `db:"metadata"   json:"metadata,omitempty"`
	CreatedAt time.Time         `db:"created_at" json:"created_at"`
}

// OAUTH 

// OAuthProvider enumerates supported OAuth providers.
type OAuthProvider string

const (
	OAuthProviderGoogle OAuthProvider = "google"
	OAuthProviderGitHub OAuthProvider = "github"
)

// OAuthConnection links an external OAuth identity to a local user.
type OAuthConnection struct {
	ID             uuid.UUID     `db:"id"               json:"id"`
	UserID         uuid.UUID     `db:"user_id"          json:"user_id"`
	Provider       OAuthProvider `db:"provider"         json:"provider"`
	ProviderUserID string        `db:"provider_user_id" json:"provider_user_id"`
	Email          string        `db:"email"            json:"email"`
	AccessToken    string        `db:"access_token"     json:"-"` // encrypted at rest
	RefreshToken   string        `db:"refresh_token"    json:"-"` // encrypted at rest
	ExpiresAt      *time.Time    `db:"expires_at"       json:"expires_at,omitempty"`
	CreatedAt      time.Time     `db:"created_at"       json:"created_at"`
	UpdatedAt      time.Time     `db:"updated_at"       json:"updated_at"`
}

// REQUEST / RESPONSE DTOs

// RegisterRequest is the payload for POST /auth/register.
type RegisterRequest struct {
	Email     string `json:"email"      validate:"required,email"`
	Password  string `json:"password"   validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name"  validate:"required"`
	Username  string `json:"username"   validate:"omitempty,min=3"`
}

// ActivateRequest is the payload for POST /auth/activate.
type ActivateRequest struct {
	Token string `json:"token" validate:"required"`
}

// LoginRequest is the payload for POST /auth/login.
type LoginRequest struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// TokenResponse is returned after a successful login or token refresh.
type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"` // always "Bearer"
	ExpiresAt    time.Time `json:"expires_at"`
	User         UserResponse `json:"user"`
}

// RefreshRequest is the payload for POST /auth/token/refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// VerifyTokenRequest is the payload for POST /auth/token/verify.
type VerifyTokenRequest struct {
	Token string `json:"token" validate:"required"`
}

// ChangePasswordRequest is the payload for POST /auth/password/change.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password"     validate:"required,min=8"`
}

// ForgotPasswordRequest is the payload for POST /auth/password/forgot.
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordRequest is the payload for POST /auth/password/reset/confirm.
type ResetPasswordRequest struct {
	Token       string `json:"token"        validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

// UpdateProfileRequest is the payload for PATCH /auth/me.
type UpdateProfileRequest struct {
	FirstName   string `json:"first_name"   validate:"omitempty"`
	LastName    string `json:"last_name"    validate:"omitempty"`
	Username    string `json:"username"     validate:"omitempty,min=3"`
	PhoneNumber string `json:"phone_number" validate:"omitempty"`
	AvatarURL   string `json:"avatar_url"   validate:"omitempty,url"`
}

// AssignRoleRequest is the payload for POST /auth/admin/users/:id/roles.
type AssignRoleRequest struct {
	RoleSlug string `json:"role_slug" validate:"required"`
}

// GrantPermissionRequest is the payload for POST /auth/admin/users/:id/permissions.
type GrantPermissionRequest struct {
	Codename string `json:"codename" validate:"required"`
}

// CreateRoleRequest is the payload for POST /auth/admin/roles.
type CreateRoleRequest struct {
	Name        string   `json:"name"        validate:"required"`
	Slug        string   `json:"slug"        validate:"required"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"` // permission codenames
}

// UserListFilter defines query params for listing users.
type UserListFilter struct {
	Role     string `json:"role"`
	IsActive *bool  `json:"is_active"`
	Search   string `json:"search"` // email or name
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

// UserResponse is the safe public shape of a user (no password hash, no sensitive fields).
type UserResponse struct {
	ID          uuid.UUID    `json:"id"`
	Email       string       `json:"email"`
	Username    string       `json:"username,omitempty"`
	FirstName   string       `json:"first_name"`
	LastName    string       `json:"last_name"`
	PhoneNumber string       `json:"phone_number,omitempty"`
	AvatarURL   string       `json:"avatar_url,omitempty"`
	IsActive    bool         `json:"is_active"`
	IsStaff     bool         `json:"is_staff"`
	IsSuperuser bool         `json:"is_superuser"`
	Roles       []Role       `json:"roles,omitempty"`
	Permissions []Permission `json:"permissions,omitempty"`
	LastLogin   *time.Time   `json:"last_login,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
}

// PaginatedUsers is the response shape for list endpoints.
type PaginatedUsers struct {
	Data     []UserResponse `json:"data"`
	Total    int            `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
}

// SeedRoleInput is used by chiauth.SeedRoles to define a role and its permissions.
type SeedRoleInput struct {
	Name        string
	Slug        string
	Description string
	IsDefault   bool
	IsSystem    bool
	Permissions []string // permission codenames
}

// MessageResponse is a generic success/info message response.
type MessageResponse struct {
	Message string `json:"message"`
}

// ErrorResponse is the standard error response shape.
type ErrorResponse struct {
	Error   string            `json:"error"`
	Details map[string]string `json:"details,omitempty"`
}
