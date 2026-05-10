package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/kimenyu/chiauth/email"
	autherrors "github.com/kimenyu/chiauth/errors"
	"github.com/kimenyu/chiauth/models"
	"github.com/kimenyu/chiauth/store"
	"golang.org/x/crypto/bcrypt"
)

// AuthService handles all auth business logic.
type AuthService struct {
	userStore    store.UserStore
	roleStore    store.RoleStore
	otpStore     store.OTPStore
	auditStore   store.AuditStore
	tokenSvc     *TokenService
	emailSender  email.Sender
	maxAttempts  int
	minPwdLength int
	requireVerify bool
	baseURL      string
	appName      string
	supportEmail string

	// Lifecycle hooks
	onUserCreated   func(*models.User)
	onUserActivated func(*models.User)
	onLogin         func(*models.User, string)
	onPasswordReset func(*models.User)
	onAccountLocked func(*models.User)
	onAccountDeleted func(*models.User)
}

// AuthServiceConfig holds dependencies for AuthService.
type AuthServiceConfig struct {
	UserStore     store.UserStore
	RoleStore     store.RoleStore
	OTPStore      store.OTPStore
	AuditStore    store.AuditStore
	TokenService  *TokenService
	EmailSender   email.Sender
	MaxAttempts   int
	MinPwdLength  int
	RequireVerify bool
	BaseURL       string
	AppName       string
	SupportEmail  string

	OnUserCreated    func(*models.User)
	OnUserActivated  func(*models.User)
	OnLogin          func(*models.User, string)
	OnPasswordReset  func(*models.User)
	OnAccountLocked  func(*models.User)
	OnAccountDeleted func(*models.User)
}

// NewAuthService constructs an AuthService.
func NewAuthService(cfg AuthServiceConfig) *AuthService {
	sender := cfg.EmailSender
	if sender == nil {
		sender = &email.StdoutSender{} // dev mode fallback
	}
	return &AuthService{
		userStore:        cfg.UserStore,
		roleStore:        cfg.RoleStore,
		otpStore:         cfg.OTPStore,
		auditStore:       cfg.AuditStore,
		tokenSvc:         cfg.TokenService,
		emailSender:      sender,
		maxAttempts:      cfg.MaxAttempts,
		minPwdLength:     cfg.MinPwdLength,
		requireVerify:    cfg.RequireVerify,
		baseURL:          cfg.BaseURL,
		appName:          cfg.AppName,
		supportEmail:     cfg.SupportEmail,
		onUserCreated:    cfg.OnUserCreated,
		onUserActivated:  cfg.OnUserActivated,
		onLogin:          cfg.OnLogin,
		onPasswordReset:  cfg.OnPasswordReset,
		onAccountLocked:  cfg.OnAccountLocked,
		onAccountDeleted: cfg.OnAccountDeleted,
	}
}

// REGISTRATION

// Register creates a new user account.
// If RequireVerify is true, the account starts inactive and a verification email is sent.
// If RequireVerify is false, the account is immediately active.
func (s *AuthService) Register(ctx context.Context, req models.RegisterRequest) (*models.User, error) {
	// Validate password length
	if len(req.Password) < s.minPwdLength {
		return nil, &autherrors.ValidationError{
			Fields: map[string]string{
				"password": fmt.Sprintf("password must be at least %d characters", s.minPwdLength),
			},
		}
	}

	// Check email uniqueness
	existing, err := s.userStore.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, autherrors.ErrEmailAlreadyExists
	}

	// Check username uniqueness if provided
	if req.Username != "" {
		byUsername, err := s.userStore.GetByUsername(ctx, req.Username)
		if err != nil {
			return nil, err
		}
		if byUsername != nil {
			return nil, autherrors.ErrUsernameAlreadyExists
		}
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		Email:        req.Email,
		Username:     req.Username,
		PasswordHash: string(hash),
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		IsActive:     !s.requireVerify, // active immediately if verification not required
	}

	if err := s.userStore.Create(ctx, user); err != nil {
		return nil, err
	}

	// Assign default role
	defaultRole, err := s.roleStore.GetRoleBySlug(ctx, "user")
	if err == nil && defaultRole != nil {
		_ = s.userStore.AssignRole(ctx, user.ID, defaultRole.ID)
	}

	// Audit
	s.audit(ctx, &user.ID, models.EventRegister, "", "")

	// Fire hook
	if s.onUserCreated != nil {
		s.onUserCreated(user)
	}

	// Send verification email
	if s.requireVerify {
		if err := s.sendVerificationEmail(ctx, user); err != nil {
			// Don't fail registration if email fails — just log it
			// The user can request a new verification email
			fmt.Printf("[chiauth] failed to send verification email to %s: %v\n", user.Email, err)
		}
	}

	return user, nil
}

// EMAIL VERIFICATION


// ActivateAccount verifies a user's email using a token sent to their inbox.
func (s *AuthService) ActivateAccount(ctx context.Context, rawToken string) (*models.User, error) {
	hash := hashToken(rawToken)

	otpToken, err := s.otpStore.GetValid(ctx, hash, models.OTPPurposeEmailVerification)
	if err != nil {
		return nil, err
	}
	if otpToken == nil {
		return nil, autherrors.ErrTokenInvalid
	}

	user, err := s.userStore.GetByID(ctx, otpToken.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, autherrors.ErrUserNotFound
	}

	user.IsActive = true
	if err := s.userStore.Update(ctx, user); err != nil {
		return nil, err
	}

	if err := s.otpStore.MarkUsed(ctx, otpToken.ID); err != nil {
		return nil, err
	}

	s.audit(ctx, &user.ID, models.EventEmailVerified, "", "")

	if s.onUserActivated != nil {
		s.onUserActivated(user)
	}

	return user, nil
}

// ResendVerification sends a new verification email.
func (s *AuthService) ResendVerification(ctx context.Context, email string) error {
	user, err := s.userStore.GetByEmail(ctx, email)
	if err != nil {
		return err
	}
	if user == nil || user.IsActive {
		// Don't reveal whether account exists or is already active
		return nil
	}
	return s.sendVerificationEmail(ctx, user)
}

// LOGIN

// Login authenticates a user and returns access + refresh tokens.
func (s *AuthService) Login(ctx context.Context, req models.LoginRequest, r *http.Request) (*models.TokenResponse, error) {
	ip := extractIP(r)

	user, err := s.userStore.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		s.audit(ctx, nil, models.EventLoginFailed, ip, r.UserAgent())
		return nil, autherrors.ErrInvalidCredentials
	}

	if user.DeletedAt != nil {
		return nil, autherrors.ErrAccountDeleted
	}
	if user.IsLocked {
		return nil, autherrors.ErrAccountLocked
	}
	if s.requireVerify && !user.IsActive {
		return nil, autherrors.ErrAccountNotActive
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		_ = s.userStore.IncrementFailedLogins(ctx, user.ID)
		// Reload to get updated count
		updated, _ := s.userStore.GetByID(ctx, user.ID)
		if updated != nil && updated.FailedLoginAttempts >= s.maxAttempts {
			_ = s.userStore.LockAccount(ctx, user.ID)
			s.audit(ctx, &user.ID, models.EventAccountLocked, ip, r.UserAgent())
			if s.onAccountLocked != nil {
				s.onAccountLocked(user)
			}
			return nil, autherrors.ErrAccountLocked
		}
		s.audit(ctx, &user.ID, models.EventLoginFailed, ip, r.UserAgent())
		return nil, autherrors.ErrInvalidCredentials
	}

	// Reset failed attempts on success
	_ = s.userStore.ResetFailedLogins(ctx, user.ID)

	// Update last login
	now := time.Now()
	user.LastLogin = &now
	user.LastLoginIP = ip
	_ = s.userStore.Update(ctx, user)

	// Issue tokens
	accessToken, expiresAt, err := s.tokenSvc.GenerateAccessToken(user)
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.tokenSvc.IssueRefreshToken(ctx, user, r)
	if err != nil {
		return nil, err
	}

	s.audit(ctx, &user.ID, models.EventLoginSuccess, ip, r.UserAgent())

	if s.onLogin != nil {
		s.onLogin(user, ip)
	}

	return &models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresAt:    expiresAt,
		User:         user.ToResponse(),
	}, nil
}

// TOKEN REFRESH

// RefreshTokens validates a refresh token and issues a new access token.
func (s *AuthService) RefreshTokens(ctx context.Context, rawRefreshToken string, r *http.Request) (*models.TokenResponse, error) {
	hash := hashToken(rawRefreshToken)

	stored, err := s.tokenSvc.GetRefreshToken(ctx, rawRefreshToken)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, autherrors.ErrTokenNotFound
	}
	if !stored.IsValid() {
		if stored.RevokedAt != nil {
			return nil, autherrors.ErrTokenRevoked
		}
		return nil, autherrors.ErrTokenExpired
	}
	_ = hash

	user, err := s.userStore.GetByID(ctx, stored.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil || !user.IsActive || user.IsLocked {
		return nil, autherrors.ErrUnauthorized
	}

	// Rotate token
	newRefresh, err := s.tokenSvc.RotateRefreshToken(ctx, rawRefreshToken, user, r)
	if err != nil {
		return nil, err
	}

	accessToken, expiresAt, err := s.tokenSvc.GenerateAccessToken(user)
	if err != nil {
		return nil, err
	}

	s.audit(ctx, &user.ID, models.EventTokenRefresh, extractIP(r), r.UserAgent())

	return &models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefresh,
		TokenType:    "Bearer",
		ExpiresAt:    expiresAt,
		User:         user.ToResponse(),
	}, nil
}

// LOGOUT

// Logout revokes the presented refresh token.
func (s *AuthService) Logout(ctx context.Context, rawRefreshToken string, userID uuid.UUID, r *http.Request) error {
	if err := s.tokenSvc.RevokeRefreshToken(ctx, rawRefreshToken); err != nil {
		return err
	}
	s.audit(ctx, &userID, models.EventLogout, extractIP(r), r.UserAgent())
	return nil
}

// LogoutAll revokes every session for the user.
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID, r *http.Request) error {
	if err := s.tokenSvc.RevokeAllUserTokens(ctx, userID); err != nil {
		return err
	}
	s.audit(ctx, &userID, models.EventLogoutAll, extractIP(r), r.UserAgent())
	return nil
}

// PASSWORD MANAGEMENT

// ChangePassword validates the current password and sets a new one.
func (s *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, req models.ChangePasswordRequest, r *http.Request) error {
	if len(req.NewPassword) < s.minPwdLength {
		return autherrors.ErrWeakPassword
	}

	user, err := s.userStore.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return autherrors.ErrUserNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		return autherrors.ErrWrongPassword
	}

	// Prevent setting same password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.NewPassword)); err == nil {
		return autherrors.ErrSamePassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.PasswordHash = string(hash)
	if err := s.userStore.Update(ctx, user); err != nil {
		return err
	}

	// Revoke all sessions — forces re-login everywhere
	_ = s.tokenSvc.RevokeAllUserTokens(ctx, userID)

	s.audit(ctx, &userID, models.EventPasswordChanged, extractIP(r), r.UserAgent())
	return nil
}

// ForgotPassword generates a password reset token and sends it by email.
// Always returns nil to prevent email enumeration attacks.
func (s *AuthService) ForgotPassword(ctx context.Context, emailAddr string, r *http.Request) error {
	user, err := s.userStore.GetByEmail(ctx, emailAddr)
	if err != nil || user == nil {
		return nil // silent: don't reveal account existence
	}

	raw, hash, err := generateSecureToken()
	if err != nil {
		return nil
	}

	otp := &models.OTPToken{
		UserID:    user.ID,
		TokenHash: hash,
		Purpose:   models.OTPPurposePasswordReset,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if err := s.otpStore.Save(ctx, otp); err != nil {
		return nil
	}

	_ = s.emailSender.SendPasswordReset(user.Email, email.PasswordResetData{
		FirstName:    user.FirstName,
		ResetURL:     fmt.Sprintf("%s/reset-password?token=%s", s.baseURL, raw),
		Token:        raw,
		ExpiresIn:    "1 hour",
		IPAddress:    extractIP(r),
		AppName:      s.appName,
		SupportEmail: s.supportEmail,
	})

	s.audit(ctx, &user.ID, models.EventPasswordResetReq, extractIP(r), r.UserAgent())
	return nil
}

// ResetPassword applies a new password using a valid reset token.
func (s *AuthService) ResetPassword(ctx context.Context, req models.ResetPasswordRequest, r *http.Request) error {
	if len(req.NewPassword) < s.minPwdLength {
		return autherrors.ErrWeakPassword
	}

	hash := hashToken(req.Token)
	otp, err := s.otpStore.GetValid(ctx, hash, models.OTPPurposePasswordReset)
	if err != nil {
		return err
	}
	if otp == nil {
		return autherrors.ErrTokenInvalid
	}

	user, err := s.userStore.GetByID(ctx, otp.UserID)
	if err != nil || user == nil {
		return autherrors.ErrUserNotFound
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.PasswordHash = string(newHash)
	if err := s.userStore.Update(ctx, user); err != nil {
		return err
	}

	_ = s.otpStore.MarkUsed(ctx, otp.ID)
	_ = s.tokenSvc.RevokeAllUserTokens(ctx, user.ID)

	s.audit(ctx, &user.ID, models.EventPasswordResetDone, extractIP(r), r.UserAgent())

	if s.onPasswordReset != nil {
		s.onPasswordReset(user)
	}
	return nil
}

// PROFILE

// UpdateProfile applies profile field changes for the authenticated user.
func (s *AuthService) UpdateProfile(ctx context.Context, userID uuid.UUID, req models.UpdateProfileRequest, r *http.Request) (*models.User, error) {
	user, err := s.userStore.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, autherrors.ErrUserNotFound
	}

	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.PhoneNumber != "" {
		user.PhoneNumber = req.PhoneNumber
	}
	if req.AvatarURL != "" {
		user.AvatarURL = req.AvatarURL
	}
	if req.Username != "" && req.Username != user.Username {
		existing, _ := s.userStore.GetByUsername(ctx, req.Username)
		if existing != nil {
			return nil, autherrors.ErrUsernameAlreadyExists
		}
		user.Username = req.Username
	}

	if err := s.userStore.Update(ctx, user); err != nil {
		return nil, err
	}

	s.audit(ctx, &userID, models.EventProfileUpdated, extractIP(r), r.UserAgent())
	return user, nil
}

// DeleteAccount soft-deletes the authenticated user's account.
func (s *AuthService) DeleteAccount(ctx context.Context, userID uuid.UUID, hardDelete bool, r *http.Request) error {
	user, err := s.userStore.GetByID(ctx, userID)
	if err != nil || user == nil {
		return autherrors.ErrUserNotFound
	}

	_ = s.tokenSvc.RevokeAllUserTokens(ctx, userID)

	if hardDelete {
		if err := s.userStore.HardDelete(ctx, userID); err != nil {
			return err
		}
	} else {
		if err := s.userStore.SoftDelete(ctx, userID); err != nil {
			return err
		}
	}

	s.audit(ctx, &userID, models.EventAccountDeleted, extractIP(r), r.UserAgent())

	if s.onAccountDeleted != nil {
		s.onAccountDeleted(user)
	}
	return nil
}

// HELPERS

func (s *AuthService) sendVerificationEmail(ctx context.Context, user *models.User) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	rawToken := hex.EncodeToString(raw)
	hash := hashToken(rawToken)

	otp := &models.OTPToken{
		UserID:    user.ID,
		TokenHash: hash,
		Purpose:   models.OTPPurposeEmailVerification,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := s.otpStore.Save(ctx, otp); err != nil {
		return err
	}

	return s.emailSender.SendVerification(user.Email, email.VerificationData{
		FirstName:       user.FirstName,
		VerificationURL: fmt.Sprintf("%s/auth/activate?token=%s", s.baseURL, rawToken),
		Token:           rawToken,
		ExpiresIn:       "24 hours",
		AppName:         s.appName,
		SupportEmail:    s.supportEmail,
	})
}

func (s *AuthService) audit(ctx context.Context, userID *uuid.UUID, event models.AuthEvent, ip, ua string) {
	if s.auditStore == nil {
		return
	}
	_ = s.auditStore.Log(ctx, &models.AuditLog{
		UserID:    userID,
		Event:     event,
		IPAddress: ip,
		UserAgent: ua,
	})
}
