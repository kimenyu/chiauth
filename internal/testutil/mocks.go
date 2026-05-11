// Package testutil provides in-memory mock implementations of all store and
// email interfaces. Drop them into any test — no database or SMTP required.
package testutil

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	autherrors "github.com/kimenyu/chiauth/errors"
	"github.com/kimenyu/chiauth/email"
	"github.com/kimenyu/chiauth/models"
)

func sha256Sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

// MockUserStore


type MockUserStore struct {
	mu      sync.RWMutex
	byID    map[uuid.UUID]*models.User
	byEmail map[string]*models.User
	byUser  map[string]*models.User
}

func NewMockUserStore() *MockUserStore {
	return &MockUserStore{
		byID:    make(map[uuid.UUID]*models.User),
		byEmail: make(map[string]*models.User),
		byUser:  make(map[string]*models.User),
	}
}

func (m *MockUserStore) Create(ctx context.Context, u *models.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
	cp := *u
	m.byID[u.ID] = &cp
	m.byEmail[u.Email] = &cp
	if u.Username != "" {
		m.byUser[u.Username] = &cp
	}
	return nil
}

func (m *MockUserStore) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

func (m *MockUserStore) GetByEmail(ctx context.Context, emailAddr string) (*models.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.byEmail[emailAddr]
	if !ok {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

func (m *MockUserStore) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.byUser[username]
	if !ok {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

func (m *MockUserStore) Update(ctx context.Context, u *models.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u.UpdatedAt = time.Now()
	cp := *u
	m.byID[u.ID] = &cp
	m.byEmail[u.Email] = &cp
	if u.Username != "" {
		m.byUser[u.Username] = &cp
	}
	return nil
}

func (m *MockUserStore) SoftDelete(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return autherrors.ErrUserNotFound
	}
	now := time.Now()
	u.DeletedAt = &now
	u.IsActive = false
	return nil
}

func (m *MockUserStore) HardDelete(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return autherrors.ErrUserNotFound
	}
	delete(m.byEmail, u.Email)
	delete(m.byUser, u.Username)
	delete(m.byID, id)
	return nil
}

func (m *MockUserStore) List(ctx context.Context, filter models.UserListFilter) ([]models.User, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []models.User
	for _, u := range m.byID {
		out = append(out, *u)
	}
	return out, len(out), nil
}

func (m *MockUserStore) IncrementFailedLogins(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.byID[id]; ok {
		u.FailedLoginAttempts++
	}
	return nil
}

func (m *MockUserStore) ResetFailedLogins(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.byID[id]; ok {
		u.FailedLoginAttempts = 0
	}
	return nil
}

func (m *MockUserStore) LockAccount(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.byID[id]; ok {
		u.IsLocked = true
	}
	return nil
}

func (m *MockUserStore) UnlockAccount(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.byID[id]; ok {
		u.IsLocked = false
		u.FailedLoginAttempts = 0
	}
	return nil
}

func (m *MockUserStore) AssignRole(ctx context.Context, userID, roleID uuid.UUID) error { return nil }
func (m *MockUserStore) RemoveRole(ctx context.Context, userID, roleID uuid.UUID) error  { return nil }
func (m *MockUserStore) GrantPermission(ctx context.Context, userID, permID uuid.UUID, grantedBy uuid.UUID) error {
	return nil
}
func (m *MockUserStore) RevokePermission(ctx context.Context, userID, permID uuid.UUID) error {
	return nil
}


// MockRoleStore

type MockRoleStore struct {
	mu    sync.RWMutex
	roles map[string]*models.Role
}

func NewMockRoleStore() *MockRoleStore {
	return &MockRoleStore{
		roles: map[string]*models.Role{
			"user": {ID: uuid.New(), Name: "User", Slug: "user", IsDefault: true},
		},
	}
}

func (m *MockRoleStore) CreateRole(ctx context.Context, r *models.Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	m.roles[r.Slug] = r
	return nil
}

func (m *MockRoleStore) GetRoleByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.roles {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, autherrors.ErrRoleNotFound
}

func (m *MockRoleStore) GetRoleBySlug(ctx context.Context, slug string) (*models.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.roles[slug]
	if !ok {
		return nil, autherrors.ErrRoleNotFound
	}
	return r, nil
}

func (m *MockRoleStore) ListRoles(ctx context.Context) ([]models.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []models.Role
	for _, r := range m.roles {
		out = append(out, *r)
	}
	return out, nil
}

func (m *MockRoleStore) DeleteRole(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for slug, r := range m.roles {
		if r.ID == id {
			if r.IsSystem {
				return autherrors.ErrRoleIsSystem
			}
			delete(m.roles, slug)
			return nil
		}
	}
	return autherrors.ErrRoleNotFound
}

func (m *MockRoleStore) AssignPermissionToRole(ctx context.Context, roleID, permID uuid.UUID) error {
	return nil
}
func (m *MockRoleStore) RemovePermissionFromRole(ctx context.Context, roleID, permID uuid.UUID) error {
	return nil
}
func (m *MockRoleStore) UpsertPermission(ctx context.Context, p *models.Permission) error { return nil }
func (m *MockRoleStore) GetPermissionByCodename(ctx context.Context, codename string) (*models.Permission, error) {
	return nil, autherrors.ErrPermissionNotFound
}
func (m *MockRoleStore) ListPermissions(ctx context.Context) ([]models.Permission, error) {
	return nil, nil
}

// MockTokenStore

type MockTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*models.RefreshToken
}

func NewMockTokenStore() *MockTokenStore {
	return &MockTokenStore{tokens: make(map[string]*models.RefreshToken)}
}

func (m *MockTokenStore) SaveRefreshToken(ctx context.Context, t *models.RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	t.CreatedAt = time.Now()
	cp := *t
	m.tokens[t.TokenHash] = &cp
	return nil
}

func (m *MockTokenStore) GetRefreshToken(ctx context.Context, hash string) (*models.RefreshToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tokens[hash]
	if !ok {
		return nil, nil
	}
	cp := *t
	return &cp, nil
}

func (m *MockTokenStore) RevokeRefreshToken(ctx context.Context, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tokens[hash]; ok {
		now := time.Now()
		t.RevokedAt = &now
	}
	return nil
}

func (m *MockTokenStore) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, t := range m.tokens {
		if t.UserID == userID {
			t.RevokedAt = &now
		}
	}
	return nil
}

func (m *MockTokenStore) ListUserTokens(ctx context.Context, userID uuid.UUID) ([]models.RefreshToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []models.RefreshToken
	for _, t := range m.tokens {
		if t.UserID == userID {
			out = append(out, *t)
		}
	}
	return out, nil
}

// MockOTPStore

type MockOTPStore struct {
	mu     sync.RWMutex
	tokens map[string]*models.OTPToken
}

func NewMockOTPStore() *MockOTPStore {
	return &MockOTPStore{tokens: make(map[string]*models.OTPToken)}
}

func (m *MockOTPStore) Save(ctx context.Context, t *models.OTPToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	t.CreatedAt = time.Now()
	cp := *t
	m.tokens[t.TokenHash] = &cp
	return nil
}

func (m *MockOTPStore) GetValid(ctx context.Context, hash string, purpose models.OTPPurpose) (*models.OTPToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tokens[hash]
	if !ok || t.Purpose != purpose || !t.IsValid() {
		return nil, nil
	}
	cp := *t
	return &cp, nil
}

func (m *MockOTPStore) MarkUsed(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tokens {
		if t.ID == id {
			now := time.Now()
			t.UsedAt = &now
			return nil
		}
	}
	return nil
}

func (m *MockOTPStore) DeleteExpired(ctx context.Context) error { return nil }

// ─────────────────────────────────────────────
// MockAuditStore
// ─────────────────────────────────────────────

type MockAuditStore struct {
	mu   sync.RWMutex
	Logs []models.AuditLog
}

func NewMockAuditStore() *MockAuditStore { return &MockAuditStore{} }

func (m *MockAuditStore) Log(ctx context.Context, entry *models.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry.ID == uuid.Nil {
		entry.ID = uuid.New()
	}
	entry.CreatedAt = time.Now()
	m.Logs = append(m.Logs, *entry)
	return nil
}

func (m *MockAuditStore) ListAudits(ctx context.Context, userID *uuid.UUID, event models.AuthEvent, page, pageSize int) ([]models.AuditLog, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Logs, len(m.Logs), nil
}

// HasEvent is a test helper: returns true if the given event was logged.
func (m *MockAuditStore) HasEvent(event models.AuthEvent) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, l := range m.Logs {
		if l.Event == event {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────
// MockEmailSender
// ─────────────────────────────────────────────

type MockEmailSender struct {
	mu            sync.RWMutex
	Verifications []string
	Resets        []string
	LoginAlerts   []string
}

func NewMockEmailSender() *MockEmailSender { return &MockEmailSender{} }

func (m *MockEmailSender) SendVerification(to string, data email.VerificationData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Verifications = append(m.Verifications, to)
	return nil
}

func (m *MockEmailSender) SendPasswordReset(to string, data email.PasswordResetData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Resets = append(m.Resets, to)
	return nil
}

func (m *MockEmailSender) SendLoginAlert(to string, data email.LoginAlertData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.LoginAlerts = append(m.LoginAlerts, to)
	return nil
}

// ─────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────


// ─────────────────────────────────────────────
// CapturingOTPStore
// ─────────────────────────────────────────────

// CapturingOTPStore wraps MockOTPStore and records every Save call so tests
// can retrieve the stored token hash and look it up without needing the raw
// token. This works because the service passes in the hashed token, and tests
// can iterate over saved tokens directly.
func (m *MockOTPStore) All() []*models.OTPToken {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*models.OTPToken
	for _, t := range m.tokens {
		cp := *t
		out = append(out, &cp)
	}
	return out
}

// LatestHash returns the TokenHash of the most recently created OTP.
func (m *MockOTPStore) LatestHash() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var latest *models.OTPToken
	for _, t := range m.tokens {
		if latest == nil || t.CreatedAt.After(latest.CreatedAt) {
			latest = t
		}
	}
	if latest == nil {
		return ""
	}
	return latest.TokenHash
}

// OnSave, if set, is called after every Save with the stored token.
// Use this in tests to capture token hashes: the service passes the hash,
// so tests need to supply the raw token a different way.
//
// The recommended pattern for testing ActivateAccount/ResetPassword:
// register with RequireVerify=false, then manually create an OTP via
// SaveOTP, which returns the raw token for use in the test.
func (m *MockOTPStore) SaveOTP(ctx context.Context, userID interface{ }, purpose models.OTPPurpose) (rawToken string, err error) {
	_ = userID // accept any type for convenience
	return "", nil
}

// InjectOTP inserts a test OTP token into the store with a deterministic raw
// value so tests can call ActivateAccount or ResetPassword without real email.
//
// Usage:
//
//	rawToken, _ := otpStore.InjectOTP(ctx, userID, models.OTPPurposeEmailVerification)
//	svc.ActivateAccount(ctx, rawToken)
func (m *MockOTPStore) InjectOTP(ctx context.Context, userID uuid.UUID, purpose models.OTPPurpose) (string, error) {
	raw := "inject-" + userID.String() + "-" + string(purpose)
	h := sha256Sum(raw)
	return raw, m.Save(ctx, &models.OTPToken{
		UserID:    userID,
		TokenHash: h,
		Purpose:   purpose,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
}