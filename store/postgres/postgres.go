// Package postgres provides the PostgreSQL implementation of all chiauth store interfaces.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/kimenyu/chiauth/models"
)

// Store implements UserStore, RoleStore, TokenStore, OTPStore, and AuditStore
// against a PostgreSQL database using sqlx.
type Store struct {
	db *sqlx.DB
}

// New returns a Store backed by the given sqlx.DB.
func New(db *sqlx.DB) *Store {
	return &Store{db: db}
}

 
// USER STORE
 
func (s *Store) Create(ctx context.Context, user *models.User) error {
    user.ID = uuid.New()
    user.CreatedAt = time.Now()
    user.UpdatedAt = time.Now()

    // Store empty username as NULL to avoid violating the unique constraint.
    // Multiple users can register without a username; NULL != NULL in Postgres.
    var username *string
    if user.Username != "" {
        username = &user.Username
    }

    _, err := s.db.ExecContext(ctx, `
        INSERT INTO chiauth_users (
            id, email, username, password_hash, first_name, last_name,
            phone_number, avatar_url, is_active, is_staff, is_superuser,
            is_locked, failed_login_attempts, created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10, $11,
            $12, $13, $14, $15
        )`,
        user.ID, user.Email, username, user.PasswordHash, user.FirstName, user.LastName,
        user.PhoneNumber, user.AvatarURL, user.IsActive, user.IsStaff, user.IsSuperuser,
        user.IsLocked, user.FailedLoginAttempts, user.CreatedAt, user.UpdatedAt,
    )
    return err
}

func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	err := s.db.GetContext(ctx, &user,
		`SELECT * FROM chiauth_users WHERE id = $1 AND deleted_at IS NULL`, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.populateRolesAndPermissions(ctx, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := s.db.GetContext(ctx, &user,
		`SELECT * FROM chiauth_users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL`, email)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.populateRolesAndPermissions(ctx, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	err := s.db.GetContext(ctx, &user,
		`SELECT * FROM chiauth_users WHERE LOWER(username) = LOWER($1) AND deleted_at IS NULL`, username)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.populateRolesAndPermissions(ctx, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Store) Update(ctx context.Context, user *models.User) error {
	user.UpdatedAt = time.Now()
	query := `
		UPDATE chiauth_users SET
			email = :email,
			username = :username,
			password_hash = :password_hash,
			first_name = :first_name,
			last_name = :last_name,
			phone_number = :phone_number,
			avatar_url = :avatar_url,
			is_active = :is_active,
			is_staff = :is_staff,
			is_superuser = :is_superuser,
			is_locked = :is_locked,
			failed_login_attempts = :failed_login_attempts,
			last_login = :last_login,
			last_login_ip = :last_login_ip,
			updated_at = :updated_at
		WHERE id = :id`
	_, err := s.db.NamedExecContext(ctx, query, user)
	return err
}

func (s *Store) SoftDelete(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`UPDATE chiauth_users SET deleted_at = $1, is_active = false, updated_at = $1 WHERE id = $2`,
		now, id)
	return err
}

func (s *Store) HardDelete(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM chiauth_users WHERE id = $1`, id)
	return err
}

func (s *Store) List(ctx context.Context, filter models.UserListFilter) ([]models.User, int, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PageSize < 1 {
		filter.PageSize = 20
	}
	offset := (filter.Page - 1) * filter.PageSize

	baseQuery := `FROM chiauth_users u WHERE u.deleted_at IS NULL`
	args := []interface{}{}
	argIdx := 1

	if filter.Search != "" {
		baseQuery += fmt.Sprintf(` AND (LOWER(u.email) LIKE LOWER($%d) OR LOWER(u.first_name) LIKE LOWER($%d) OR LOWER(u.last_name) LIKE LOWER($%d))`, argIdx, argIdx, argIdx)
		args = append(args, "%"+filter.Search+"%")
		argIdx++
	}
	if filter.IsActive != nil {
		baseQuery += fmt.Sprintf(` AND u.is_active = $%d`, argIdx)
		args = append(args, *filter.IsActive)
		argIdx++
	}

	var total int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) "+baseQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	args = append(args, filter.PageSize, offset)
	rows, err := s.db.QueryxContext(ctx,
		fmt.Sprintf("SELECT u.* "+baseQuery+" ORDER BY u.created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.StructScan(&u); err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, nil
}

func (s *Store) IncrementFailedLogins(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE chiauth_users SET failed_login_attempts = failed_login_attempts + 1, updated_at = NOW() WHERE id = $1`, id)
	return err
}

func (s *Store) ResetFailedLogins(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE chiauth_users SET failed_login_attempts = 0, updated_at = NOW() WHERE id = $1`, id)
	return err
}

func (s *Store) LockAccount(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE chiauth_users SET is_locked = true, updated_at = NOW() WHERE id = $1`, id)
	return err
}

func (s *Store) UnlockAccount(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE chiauth_users SET is_locked = false, failed_login_attempts = 0, updated_at = NOW() WHERE id = $1`, id)
	return err
}

func (s *Store) AssignRole(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO chiauth_user_roles (user_id, role_id, created_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING`,
		userID, roleID)
	return err
}

func (s *Store) RemoveRole(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM chiauth_user_roles WHERE user_id = $1 AND role_id = $2`, userID, roleID)
	return err
}

func (s *Store) GrantPermission(ctx context.Context, userID, permissionID, grantedBy uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO chiauth_user_permissions (user_id, permission_id, granted_by, created_at) VALUES ($1, $2, $3, NOW()) ON CONFLICT DO NOTHING`,
		userID, permissionID, grantedBy)
	return err
}

func (s *Store) RevokePermission(ctx context.Context, userID, permissionID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM chiauth_user_permissions WHERE user_id = $1 AND permission_id = $2`, userID, permissionID)
	return err
}

// populateRolesAndPermissions loads roles (with their permissions) and direct permissions onto a user.
func (s *Store) populateRolesAndPermissions(ctx context.Context, user *models.User) error {
	// Load roles
	roles := []models.Role{}
	err := s.db.SelectContext(ctx, &roles, `
		SELECT r.* FROM chiauth_roles r
		INNER JOIN chiauth_user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1`, user.ID)
	if err != nil {
		return err
	}
	// Load permissions for each role
	for i, role := range roles {
		perms := []models.Permission{}
		err := s.db.SelectContext(ctx, &perms, `
			SELECT p.* FROM chiauth_permissions p
			INNER JOIN chiauth_role_permissions rp ON rp.permission_id = p.id
			WHERE rp.role_id = $1`, role.ID)
		if err != nil {
			return err
		}
		roles[i].Permissions = perms
	}
	user.Roles = roles

	// Load direct permissions
	perms := []models.Permission{}
	err = s.db.SelectContext(ctx, &perms, `
		SELECT p.* FROM chiauth_permissions p
		INNER JOIN chiauth_user_permissions up ON up.permission_id = p.id
		WHERE up.user_id = $1`, user.ID)
	if err != nil {
		return err
	}
	user.Permissions = perms
	return nil
}

 
// ROLE STORE

func (s *Store) CreateRole(ctx context.Context, role *models.Role) error {
	role.ID = uuid.New()
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()
	_, err := s.db.NamedExecContext(ctx, `
		INSERT INTO chiauth_roles (id, name, slug, description, is_default, is_system, created_at, updated_at)
		VALUES (:id, :name, :slug, :description, :is_default, :is_system, :created_at, :updated_at)`, role)
	return err
}

func (s *Store) GetRoleByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	var role models.Role
	err := s.db.GetContext(ctx, &role, `SELECT * FROM chiauth_roles WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &role, s.loadRolePermissions(ctx, &role)
}

func (s *Store) GetRoleBySlug(ctx context.Context, slug string) (*models.Role, error) {
	var role models.Role
	err := s.db.GetContext(ctx, &role, `SELECT * FROM chiauth_roles WHERE slug = $1`, slug)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &role, s.loadRolePermissions(ctx, &role)
}

func (s *Store) ListRoles(ctx context.Context) ([]models.Role, error) {
	var roles []models.Role
	if err := s.db.SelectContext(ctx, &roles, `SELECT * FROM chiauth_roles ORDER BY name`); err != nil {
		return nil, err
	}
	for i := range roles {
		if err := s.loadRolePermissions(ctx, &roles[i]); err != nil {
			return nil, err
		}
	}
	return roles, nil
}

func (s *Store) DeleteRole(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM chiauth_roles WHERE id = $1 AND is_system = false`, id)
	return err
}

func (s *Store) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO chiauth_role_permissions (role_id, permission_id, created_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING`,
		roleID, permissionID)
	return err
}

func (s *Store) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM chiauth_role_permissions WHERE role_id = $1 AND permission_id = $2`, roleID, permissionID)
	return err
}

func (s *Store) UpsertPermission(ctx context.Context, p *models.Permission) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	p.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO chiauth_permissions (id, codename, resource, action, description, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (codename) DO UPDATE SET
			resource = EXCLUDED.resource,
			action = EXCLUDED.action,
			description = EXCLUDED.description`,
		p.ID, p.Codename, p.Resource, p.Action, p.Description, p.CreatedAt)
	return err
}

func (s *Store) GetPermissionByCodename(ctx context.Context, codename string) (*models.Permission, error) {
	var p models.Permission
	err := s.db.GetContext(ctx, &p, `SELECT * FROM chiauth_permissions WHERE codename = $1`, codename)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

func (s *Store) ListPermissions(ctx context.Context) ([]models.Permission, error) {
	var perms []models.Permission
	err := s.db.SelectContext(ctx, &perms, `SELECT * FROM chiauth_permissions ORDER BY resource, action`)
	return perms, err
}

func (s *Store) loadRolePermissions(ctx context.Context, role *models.Role) error {
	perms := []models.Permission{}
	err := s.db.SelectContext(ctx, &perms, `
		SELECT p.* FROM chiauth_permissions p
		INNER JOIN chiauth_role_permissions rp ON rp.permission_id = p.id
		WHERE rp.role_id = $1`, role.ID)
	if err != nil {
		return err
	}
	role.Permissions = perms
	return nil
}


// TOKEN STORE


func (s *Store) SaveRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	token.ID = uuid.New()
	token.CreatedAt = time.Now()
	_, err := s.db.NamedExecContext(ctx, `
		INSERT INTO chiauth_refresh_tokens (id, user_id, token_hash, device_info, ip_address, user_agent, expires_at, created_at)
		VALUES (:id, :user_id, :token_hash, :device_info, :ip_address, :user_agent, :expires_at, :created_at)`, token)
	return err
}

func (s *Store) GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := s.db.GetContext(ctx, &token, `SELECT * FROM chiauth_refresh_tokens WHERE token_hash = $1`, tokenHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &token, err
}

func (s *Store) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE chiauth_refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1`, tokenHash)
	return err
}

func (s *Store) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE chiauth_refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}

func (s *Store) ListUserTokens(ctx context.Context, userID uuid.UUID) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	err := s.db.SelectContext(ctx, &tokens, `
		SELECT * FROM chiauth_refresh_tokens
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC`, userID)
	return tokens, err
}
 
// OTP STORE

func (s *Store) Save(ctx context.Context, token *models.OTPToken) error {
	token.ID = uuid.New()
	token.CreatedAt = time.Now()
	_, err := s.db.NamedExecContext(ctx, `
		INSERT INTO chiauth_otp_tokens (id, user_id, token_hash, purpose, expires_at, created_at)
		VALUES (:id, :user_id, :token_hash, :purpose, :expires_at, :created_at)`, token)
	return err
}

func (s *Store) GetValid(ctx context.Context, tokenHash string, purpose models.OTPPurpose) (*models.OTPToken, error) {
	var token models.OTPToken
	err := s.db.GetContext(ctx, &token, `
		SELECT * FROM chiauth_otp_tokens
		WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > NOW()`, tokenHash, purpose)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &token, err
}

func (s *Store) MarkUsed(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE chiauth_otp_tokens SET used_at = NOW() WHERE id = $1`, id)
	return err
}

func (s *Store) DeleteExpired(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM chiauth_otp_tokens WHERE expires_at < NOW() OR used_at IS NOT NULL`)
	return err
}

// AUDIT STORE

func (s *Store) Log(ctx context.Context, entry *models.AuditLog) error {
	entry.ID = uuid.New()
	entry.CreatedAt = time.Now()

	metaJSON, err := json.Marshal(entry.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO chiauth_audit_logs (id, user_id, event, ip_address, user_agent, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.ID, entry.UserID, entry.Event, entry.IPAddress, entry.UserAgent, metaJSON, entry.CreatedAt)
	return err
}

func (s *Store) ListAudits(ctx context.Context, userID *uuid.UUID, event models.AuthEvent, page, pageSize int) ([]models.AuditLog, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	query := `FROM chiauth_audit_logs WHERE 1=1`
	args := []interface{}{}
	idx := 1

	if userID != nil {
		query += fmt.Sprintf(" AND user_id = $%d", idx)
		args = append(args, *userID)
		idx++
	}
	if event != "" {
		query += fmt.Sprintf(" AND event = $%d", idx)
		args = append(args, string(event))
		idx++
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) "+query, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, pageSize, offset)
	rows, err := s.db.QueryxContext(ctx,
		fmt.Sprintf("SELECT * "+query+" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", idx, idx+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		if err := rows.StructScan(&l); err != nil {
			return nil, 0, err
		}
		logs = append(logs, l)
	}
	return logs, total, nil
}
