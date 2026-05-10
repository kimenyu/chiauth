// Package store defines the persistence interfaces for chiauth.
// Swap in any implementation by satisfying these interfaces.
package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/kimenyu/chiauth/models"
)

// UserStore handles all user persistence.
type UserStore interface {
	// Create inserts a new user and returns it with ID and timestamps set.
	Create(ctx context.Context, user *models.User) error

	// GetByID fetches a user with their roles and permissions populated.
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)

	// GetByEmail fetches a user by email (case-insensitive).
	GetByEmail(ctx context.Context, email string) (*models.User, error)

	// GetByUsername fetches a user by username.
	GetByUsername(ctx context.Context, username string) (*models.User, error)

	// Update persists changes to an existing user.
	Update(ctx context.Context, user *models.User) error

	// SoftDelete sets DeletedAt and deactivates the user.
	SoftDelete(ctx context.Context, id uuid.UUID) error

	// HardDelete permanently removes the user and all related records.
	HardDelete(ctx context.Context, id uuid.UUID) error

	// List returns a paginated, filtered list of users.
	List(ctx context.Context, filter models.UserListFilter) ([]models.User, int, error)

	// IncrementFailedLogins increments the failed login counter.
	IncrementFailedLogins(ctx context.Context, id uuid.UUID) error

	// ResetFailedLogins resets the failed login counter to zero.
	ResetFailedLogins(ctx context.Context, id uuid.UUID) error

	// LockAccount sets IsLocked = true.
	LockAccount(ctx context.Context, id uuid.UUID) error

	// UnlockAccount sets IsLocked = false and resets failed login counter.
	UnlockAccount(ctx context.Context, id uuid.UUID) error

	// AssignRole adds a role to a user.
	AssignRole(ctx context.Context, userID, roleID uuid.UUID) error

	// RemoveRole removes a role from a user.
	RemoveRole(ctx context.Context, userID, roleID uuid.UUID) error

	// GrantPermission adds a direct permission to a user.
	GrantPermission(ctx context.Context, userID, permissionID uuid.UUID, grantedBy uuid.UUID) error

	// RevokePermission removes a direct permission from a user.
	RevokePermission(ctx context.Context, userID, permissionID uuid.UUID) error
}

// RoleStore handles role and permission persistence.
type RoleStore interface {
	// CreateRole inserts a new role.
	CreateRole(ctx context.Context, role *models.Role) error

	// GetRoleByID returns a role with its permissions.
	GetRoleByID(ctx context.Context, id uuid.UUID) (*models.Role, error)

	// GetRoleBySlug returns a role with its permissions.
	GetRoleBySlug(ctx context.Context, slug string) (*models.Role, error)

	// ListRoles returns all roles.
	ListRoles(ctx context.Context) ([]models.Role, error)

	// DeleteRole removes a role. Fails on system roles.
	DeleteRole(ctx context.Context, id uuid.UUID) error

	// AssignPermissionToRole links a permission to a role.
	AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error

	// RemovePermissionFromRole removes a permission from a role.
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error

	// UpsertPermission creates or updates a permission by codename.
	UpsertPermission(ctx context.Context, p *models.Permission) error

	// GetPermissionByCodename returns a permission by its codename.
	GetPermissionByCodename(ctx context.Context, codename string) (*models.Permission, error)

	// ListPermissions returns all permissions.
	ListPermissions(ctx context.Context) ([]models.Permission, error)
}

// TokenStore handles refresh token persistence.
type TokenStore interface {
	// SaveRefreshToken persists a new refresh token.
	SaveRefreshToken(ctx context.Context, token *models.RefreshToken) error

	// GetRefreshToken fetches a token by its hash.
	GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error)

	// RevokeRefreshToken marks a single token as revoked.
	RevokeRefreshToken(ctx context.Context, tokenHash string) error

	// RevokeAllUserTokens revokes every refresh token for a user.
	// Called on logout-all, password change, or suspected token theft.
	RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error

	// ListUserTokens returns all active tokens for a user (for session management).
	ListUserTokens(ctx context.Context, userID uuid.UUID) ([]models.RefreshToken, error)
}

// OTPStore handles one-time token persistence.
type OTPStore interface {
	// Save persists a new OTP token.
	Save(ctx context.Context, token *models.OTPToken) error

	// GetValid fetches a valid (not used, not expired) token by hash and purpose.
	GetValid(ctx context.Context, tokenHash string, purpose models.OTPPurpose) (*models.OTPToken, error)

	// MarkUsed sets UsedAt on a token, making it non-reusable.
	MarkUsed(ctx context.Context, id uuid.UUID) error

	// DeleteExpired purges expired tokens. Call from a scheduled job.
	DeleteExpired(ctx context.Context) error
}

// AuditStore handles audit log persistence.
type AuditStore interface {
	// Log writes a new audit event.
	Log(ctx context.Context, entry *models.AuditLog) error

	// List returns paginated audit logs with optional filters.
	ListAudits(ctx context.Context, userID *uuid.UUID, event models.AuthEvent, page, pageSize int) ([]models.AuditLog, int, error)
}
