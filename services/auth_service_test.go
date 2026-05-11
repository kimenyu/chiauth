package services_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kimenyu/chiauth/internal/testutil"
	autherrors "github.com/kimenyu/chiauth/errors"
	"github.com/kimenyu/chiauth/models"
	"github.com/kimenyu/chiauth/services"
)

// Helpers

func newTestSvc(t *testing.T) (
	*services.AuthService,
	*testutil.MockUserStore,
	*testutil.MockOTPStore,
	*testutil.MockAuditStore,
	*testutil.MockEmailSender,
) {
	t.Helper()
	us := testutil.NewMockUserStore()
	rs := testutil.NewMockRoleStore()
	ts := testutil.NewMockTokenStore()
	os := testutil.NewMockOTPStore()
	as := testutil.NewMockAuditStore()
	em := testutil.NewMockEmailSender()

	tokenSvc := services.NewTokenService(
		"test-secret-key",
		15*time.Minute,
		7*24*time.Hour,
		true,
		ts,
	)

	svc := services.NewAuthService(services.AuthServiceConfig{
		UserStore:    us,
		RoleStore:    rs,
		OTPStore:     os,
		AuditStore:   as,
		TokenService: tokenSvc,
		EmailSender:  em,
		MaxAttempts:  3,
		MinPwdLength: 8,
		BaseURL:      "http://localhost:8080",
		AppName:      "TestApp",
		SupportEmail: "support@test.com",
	})
	return svc, us, os, as, em
}

func fakeReq() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", nil)
}
// Register

func TestRegister_Success(t *testing.T) {
	svc, us, _, audit, _ := newTestSvc(t)

	user, err := svc.Register(context.Background(), models.RegisterRequest{
		Email:     "alice@example.com",
		Password:  "securepass",
		FirstName: "Alice",
		LastName:  "Smith",
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Errorf("email mismatch: got %q", user.Email)
	}
	if user.PasswordHash == "" {
		t.Error("password hash should not be empty")
	}
	if user.PasswordHash == "securepass" {
		t.Error("password should be hashed, not stored plain")
	}
	// Active immediately because requireVerify is false
	if !user.IsActive {
		t.Error("user should be active when verification not required")
	}

	// Persisted in store
	stored, _ := us.GetByEmail(context.Background(), "alice@example.com")
	if stored == nil {
		t.Error("user not found in store after registration")
	}

	// Audit log
	if !audit.HasEvent(models.EventRegister) {
		t.Error("expected register event in audit log")
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	svc, _, _, _, _ := newTestSvc(t)

	_, err := svc.Register(context.Background(), models.RegisterRequest{
		Email:    "bob@example.com",
		Password: "short",
	})

	if err == nil {
		t.Fatal("expected error for short password")
	}
	var ve *autherrors.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	svc, _, _, _, _ := newTestSvc(t)
	ctx := context.Background()
	req := models.RegisterRequest{Email: "dup@example.com", Password: "securepass"}

	if _, err := svc.Register(ctx, req); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}
	_, err := svc.Register(ctx, req)
	if !errors.Is(err, autherrors.ErrEmailAlreadyExists) {
		t.Errorf("expected ErrEmailAlreadyExists, got %v", err)
	}
}

func TestRegister_DuplicateUsername(t *testing.T) {
	svc, _, _, _, _ := newTestSvc(t)
	ctx := context.Background()

	if _, err := svc.Register(ctx, models.RegisterRequest{
		Email: "user1@example.com", Password: "securepass", Username: "johndoe",
	}); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}
	_, err := svc.Register(ctx, models.RegisterRequest{
		Email: "user2@example.com", Password: "securepass", Username: "johndoe",
	})
	if !errors.Is(err, autherrors.ErrUsernameAlreadyExists) {
		t.Errorf("expected ErrUsernameAlreadyExists, got %v", err)
	}
}

func TestRegister_WithVerification_SendsEmail(t *testing.T) {
	us := testutil.NewMockUserStore()
	rs := testutil.NewMockRoleStore()
	ts := testutil.NewMockTokenStore()
	os := testutil.NewMockOTPStore()
	em := testutil.NewMockEmailSender()

	tokenSvc := services.NewTokenService("secret", 15*time.Minute, 7*24*time.Hour, true, ts)
	svc := services.NewAuthService(services.AuthServiceConfig{
		UserStore:     us,
		RoleStore:     rs,
		OTPStore:      os,
		TokenService:  tokenSvc,
		EmailSender:   em,
		RequireVerify: true,
		MinPwdLength:  8,
	})

	user, err := svc.Register(context.Background(), models.RegisterRequest{
		Email:    "verify@example.com",
		Password: "securepass",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.IsActive {
		t.Error("user should not be active before email verification")
	}
	if len(em.Verifications) != 1 || em.Verifications[0] != "verify@example.com" {
		t.Errorf("expected verification email sent, got %v", em.Verifications)
	}
}

func TestRegister_HookFired(t *testing.T) {
	svc, _, _, _, _ := newTestSvc(t)
	// Rebuild with a hook
	us := testutil.NewMockUserStore()
	rs := testutil.NewMockRoleStore()
	ts := testutil.NewMockTokenStore()

	var hookUser *models.User
	tokenSvc := services.NewTokenService("secret", 15*time.Minute, 7*24*time.Hour, true, ts)
	svc = services.NewAuthService(services.AuthServiceConfig{
		UserStore:     us,
		RoleStore:     rs,
		OTPStore:      testutil.NewMockOTPStore(),
		TokenService:  tokenSvc,
		MinPwdLength:  8,
		OnUserCreated: func(u *models.User) { hookUser = u },
	})

	if _, err := svc.Register(context.Background(), models.RegisterRequest{
		Email:    "hook@example.com",
		Password: "securepass",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hookUser == nil || hookUser.Email != "hook@example.com" {
		t.Error("OnUserCreated hook not fired correctly")
	}
}

// ActivateAccount

func TestActivateAccount_Success(t *testing.T) {
	us := testutil.NewMockUserStore()
	os := testutil.NewMockOTPStore()
	ts := testutil.NewMockTokenStore()
	em := testutil.NewMockEmailSender()

	var activatedUser *models.User
	tokenSvc := services.NewTokenService("secret", 15*time.Minute, 7*24*time.Hour, true, ts)
	svc := services.NewAuthService(services.AuthServiceConfig{
		UserStore:       us,
		RoleStore:       testutil.NewMockRoleStore(),
		OTPStore:        os,
		TokenService:    tokenSvc,
		EmailSender:     em,
		RequireVerify:   true,
		MinPwdLength:    8,
		OnUserActivated: func(u *models.User) { activatedUser = u },
	})

	ctx := context.Background()
	user, err := svc.Register(ctx, models.RegisterRequest{
		Email:    "activate@example.com",
		Password: "securepass",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if user.IsActive {
		t.Fatal("user should start inactive")
	}

	// Inject a test OTP directly — bypasses email delivery.
	rawToken, err := os.InjectOTP(ctx, user.ID, models.OTPPurposeEmailVerification)
	if err != nil {
		t.Fatalf("inject OTP failed: %v", err)
	}

	activated, err := svc.ActivateAccount(ctx, rawToken)
	if err != nil {
		t.Fatalf("activation failed: %v", err)
	}
	if !activated.IsActive {
		t.Error("user should be active after activation")
	}
	if activatedUser == nil {
		t.Error("OnUserActivated hook not fired")
	}
}

func TestActivateAccount_InvalidToken(t *testing.T) {
	svc, _, _, _, _ := newTestSvc(t)
	_, err := svc.ActivateAccount(context.Background(), "totally-fake-token")
	if !errors.Is(err, autherrors.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid, got %v", err)
	}
}

// Login

func registerActive(t *testing.T, svc *services.AuthService, emailAddr, password string) {
	t.Helper()
	_, err := svc.Register(context.Background(), models.RegisterRequest{
		Email:    emailAddr,
		Password: password,
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
}

func TestLogin_Success(t *testing.T) {
	svc, _, _, audit, _ := newTestSvc(t)
	registerActive(t, svc, "login@example.com", "securepass")

	resp, err := svc.Login(context.Background(), models.LoginRequest{
		Email:    "login@example.com",
		Password: "securepass",
	}, fakeReq())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("access token should not be empty")
	}
	if resp.RefreshToken == "" {
		t.Error("refresh token should not be empty")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected Bearer, got %q", resp.TokenType)
	}
	if !audit.HasEvent(models.EventLoginSuccess) {
		t.Error("expected login_success audit event")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	svc, _, _, _, _ := newTestSvc(t)
	registerActive(t, svc, "pw@example.com", "securepass")

	_, err := svc.Login(context.Background(), models.LoginRequest{
		Email:    "pw@example.com",
		Password: "wrongpass",
	}, fakeReq())

	if !errors.Is(err, autherrors.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLogin_UnknownEmail(t *testing.T) {
	svc, _, _, _, _ := newTestSvc(t)

	_, err := svc.Login(context.Background(), models.LoginRequest{
		Email:    "ghost@example.com",
		Password: "anything",
	}, fakeReq())

	if !errors.Is(err, autherrors.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLogin_AccountLockAfterMaxAttempts(t *testing.T) {
	svc, us, _, _, _ := newTestSvc(t)
	registerActive(t, svc, "lock@example.com", "securepass")

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		svc.Login(ctx, models.LoginRequest{
			Email:    "lock@example.com",
			Password: "wrongpass",
		}, fakeReq())
	}

	u, _ := us.GetByEmail(ctx, "lock@example.com")
	if u == nil {
		t.Fatal("user not found")
	}
	if !u.IsLocked {
		t.Error("account should be locked after 3 failed attempts")
	}

	// Further login should return locked error
	_, err := svc.Login(ctx, models.LoginRequest{
		Email:    "lock@example.com",
		Password: "securepass",
	}, fakeReq())
	if !errors.Is(err, autherrors.ErrAccountLocked) {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}
}

func TestLogin_RequireVerify_InactiveAccount(t *testing.T) {
	us := testutil.NewMockUserStore()
	ts := testutil.NewMockTokenStore()
	tokenSvc := services.NewTokenService("secret", 15*time.Minute, 7*24*time.Hour, true, ts)
	svc := services.NewAuthService(services.AuthServiceConfig{
		UserStore:     us,
		RoleStore:     testutil.NewMockRoleStore(),
		OTPStore:      testutil.NewMockOTPStore(),
		TokenService:  tokenSvc,
		RequireVerify: true,
		MinPwdLength:  8,
	})

	svc.Register(context.Background(), models.RegisterRequest{
		Email:    "unverified@example.com",
		Password: "securepass",
	})

	_, err := svc.Login(context.Background(), models.LoginRequest{
		Email:    "unverified@example.com",
		Password: "securepass",
	}, fakeReq())

	if !errors.Is(err, autherrors.ErrAccountNotActive) {
		t.Errorf("expected ErrAccountNotActive, got %v", err)
	}
}

// ChangePassword

func TestChangePassword_Success(t *testing.T) {
	svc, us, _, _, _ := newTestSvc(t)
	registerActive(t, svc, "chpw@example.com", "oldpassword")

	u, _ := us.GetByEmail(context.Background(), "chpw@example.com")

	err := svc.ChangePassword(context.Background(), u.ID, models.ChangePasswordRequest{
		CurrentPassword: "oldpassword",
		NewPassword:     "newpassword",
	}, fakeReq())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestChangePassword_WrongCurrent(t *testing.T) {
	svc, us, _, _, _ := newTestSvc(t)
	registerActive(t, svc, "chpw2@example.com", "oldpassword")
	u, _ := us.GetByEmail(context.Background(), "chpw2@example.com")

	err := svc.ChangePassword(context.Background(), u.ID, models.ChangePasswordRequest{
		CurrentPassword: "wrongcurrent",
		NewPassword:     "newpassword",
	}, fakeReq())

	if !errors.Is(err, autherrors.ErrWrongPassword) {
		t.Errorf("expected ErrWrongPassword, got %v", err)
	}
}

func TestChangePassword_SamePassword(t *testing.T) {
	svc, us, _, _, _ := newTestSvc(t)
	registerActive(t, svc, "chpw3@example.com", "samepassword")
	u, _ := us.GetByEmail(context.Background(), "chpw3@example.com")

	err := svc.ChangePassword(context.Background(), u.ID, models.ChangePasswordRequest{
		CurrentPassword: "samepassword",
		NewPassword:     "samepassword",
	}, fakeReq())

	if !errors.Is(err, autherrors.ErrSamePassword) {
		t.Errorf("expected ErrSamePassword, got %v", err)
	}
}

func TestChangePassword_WeakNew(t *testing.T) {
	svc, us, _, _, _ := newTestSvc(t)
	registerActive(t, svc, "chpw4@example.com", "oldpassword")
	u, _ := us.GetByEmail(context.Background(), "chpw4@example.com")

	err := svc.ChangePassword(context.Background(), u.ID, models.ChangePasswordRequest{
		CurrentPassword: "oldpassword",
		NewPassword:     "weak",
	}, fakeReq())

	if !errors.Is(err, autherrors.ErrWeakPassword) {
		t.Errorf("expected ErrWeakPassword, got %v", err)
	}
}

// ForgotPassword / ResetPassword

func TestForgotPassword_SilentForUnknownEmail(t *testing.T) {
	svc, _, _, _, _ := newTestSvc(t)
	// Should not return an error even for non-existent emails
	err := svc.ForgotPassword(context.Background(), "ghost@example.com", fakeReq())
	if err != nil {
		t.Errorf("expected nil for unknown email, got %v", err)
	}
}

func TestResetPassword_Success(t *testing.T) {
	us := testutil.NewMockUserStore()
	os := testutil.NewMockOTPStore()
	ts := testutil.NewMockTokenStore()
	tokenSvc := services.NewTokenService("secret", 15*time.Minute, 7*24*time.Hour, true, ts)
	svc := services.NewAuthService(services.AuthServiceConfig{
		UserStore:    us,
		RoleStore:    testutil.NewMockRoleStore(),
		OTPStore:     os,
		TokenService: tokenSvc,
		MinPwdLength: 8,
	})

	ctx := context.Background()
	svc.Register(ctx, models.RegisterRequest{Email: "reset@example.com", Password: "oldpassword"})

	svc.ForgotPassword(ctx, "reset@example.com", fakeReq())

	// Get the registered user's ID so we can inject a test reset token.
	resetUser, _ := us.GetByEmail(ctx, "reset@example.com")
	rawToken, err := os.InjectOTP(ctx, resetUser.ID, models.OTPPurposePasswordReset)
	if err != nil {
		t.Fatalf("inject OTP failed: %v", err)
	}

	resetErr := svc.ResetPassword(ctx, models.ResetPasswordRequest{
		Token:       rawToken,
		NewPassword: "brandnewpass",
	}, fakeReq())
	if resetErr != nil {
		t.Fatalf("reset failed: %v", resetErr)
	}

	// Should be able to log in with the new password
	_, err = svc.Login(ctx, models.LoginRequest{
		Email:    "reset@example.com",
		Password: "brandnewpass",
	}, fakeReq())
	if err != nil {
		t.Errorf("login with new password failed: %v", err)
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	svc, _, _, _, _ := newTestSvc(t)
	err := svc.ResetPassword(context.Background(), models.ResetPasswordRequest{
		Token:       "bad-token",
		NewPassword: "newpassword",
	}, fakeReq())
	if !errors.Is(err, autherrors.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid, got %v", err)
	}
}


// UpdateProfile


func TestUpdateProfile_Success(t *testing.T) {
	svc, us, _, _, _ := newTestSvc(t)
	registerActive(t, svc, "profile@example.com", "securepass")
	u, _ := us.GetByEmail(context.Background(), "profile@example.com")

	updated, err := svc.UpdateProfile(context.Background(), u.ID, models.UpdateProfileRequest{
		FirstName: "Jane",
		LastName:  "Doe",
	}, fakeReq())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.FirstName != "Jane" || updated.LastName != "Doe" {
		t.Errorf("profile not updated: %+v", updated)
	}
}

func TestUpdateProfile_DuplicateUsername(t *testing.T) {
	svc, us, _, _, _ := newTestSvc(t)
	registerActive(t, svc, "p1@example.com", "securepass")
	svc.Register(context.Background(), models.RegisterRequest{
		Email: "p2@example.com", Password: "securepass", Username: "taken",
	})

	u, _ := us.GetByEmail(context.Background(), "p1@example.com")
	_, err := svc.UpdateProfile(context.Background(), u.ID, models.UpdateProfileRequest{
		Username: "taken",
	}, fakeReq())
	if !errors.Is(err, autherrors.ErrUsernameAlreadyExists) {
		t.Errorf("expected ErrUsernameAlreadyExists, got %v", err)
	}
}

// DeleteAccount

func TestDeleteAccount_SoftDelete(t *testing.T) {
	svc, us, _, _, _ := newTestSvc(t)
	registerActive(t, svc, "del@example.com", "securepass")
	u, _ := us.GetByEmail(context.Background(), "del@example.com")

	err := svc.DeleteAccount(context.Background(), u.ID, false, fakeReq())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stored, _ := us.GetByID(context.Background(), u.ID)
	if stored.DeletedAt == nil {
		t.Error("expected DeletedAt to be set after soft delete")
	}
}

func TestDeleteAccount_HardDelete(t *testing.T) {
	svc, us, _, _, _ := newTestSvc(t)
	registerActive(t, svc, "hard@example.com", "securepass")
	u, _ := us.GetByEmail(context.Background(), "hard@example.com")

	err := svc.DeleteAccount(context.Background(), u.ID, true, fakeReq())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stored, _ := us.GetByID(context.Background(), u.ID)
	if stored != nil {
		t.Error("user should be gone after hard delete")
	}
}