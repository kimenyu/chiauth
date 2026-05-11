package services_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kimenyu/chiauth/internal/testutil"
	"github.com/kimenyu/chiauth/models"
	"github.com/kimenyu/chiauth/services"
	"github.com/google/uuid"
)

func newTokenSvc(t *testing.T) (*services.TokenService, *testutil.MockTokenStore) {
	t.Helper()
	ts := testutil.NewMockTokenStore()
	svc := services.NewTokenService("test-secret", 15*time.Minute, 7*24*time.Hour, true, ts)
	return svc, ts
}

func fakeUser() *models.User {
	return &models.User{
		ID:          uuid.New(),
		Email:       "user@example.com",
		IsActive:    true,
		IsSuperuser: false,
		Roles:       []models.Role{{Slug: "user"}},
	}
}

func TestGenerateAccessToken_ValidJWT(t *testing.T) {
	svc, _ := newTokenSvc(t)
	user := fakeUser()

	tokenStr, expiresAt, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokenStr == "" {
		t.Error("token string should not be empty")
	}
	if expiresAt.Before(time.Now()) {
		t.Error("expiresAt should be in the future")
	}
}

func TestValidateAccessToken_RoundTrip(t *testing.T) {
	svc, _ := newTokenSvc(t)
	user := fakeUser()

	tokenStr, _, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("generation failed: %v", err)
	}

	claims, err := svc.ValidateAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if claims.UserID != user.ID {
		t.Errorf("user ID mismatch: got %v, want %v", claims.UserID, user.ID)
	}
	if claims.Email != user.Email {
		t.Errorf("email mismatch: got %q, want %q", claims.Email, user.Email)
	}
}

func TestValidateAccessToken_Tampered(t *testing.T) {
	svc, _ := newTokenSvc(t)
	user := fakeUser()
	tokenStr, _, _ := svc.GenerateAccessToken(user)

	_, err := svc.ValidateAccessToken(tokenStr + "tampered")
	if err == nil {
		t.Error("expected error for tampered token")
	}
}

func TestValidateAccessToken_WrongSecret(t *testing.T) {
	ts := testutil.NewMockTokenStore()
	svc1 := services.NewTokenService("secret-A", 15*time.Minute, 7*24*time.Hour, true, ts)
	svc2 := services.NewTokenService("secret-B", 15*time.Minute, 7*24*time.Hour, true, ts)

	tokenStr, _, _ := svc1.GenerateAccessToken(fakeUser())
	_, err := svc2.ValidateAccessToken(tokenStr)
	if err == nil {
		t.Error("expected error when validating with a different secret")
	}
}

func TestIssueAndGetRefreshToken(t *testing.T) {
	svc, _ := newTokenSvc(t)
	user := fakeUser()
	req := httptest.NewRequest("POST", "/", nil)

	raw, err := svc.IssueRefreshToken(context.Background(), user, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw == "" {
		t.Error("refresh token should not be empty")
	}

	stored, err := svc.GetRefreshToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if stored == nil {
		t.Fatal("stored token not found")
	}
	if stored.UserID != user.ID {
		t.Errorf("user ID mismatch: got %v", stored.UserID)
	}
	if !stored.IsValid() {
		t.Error("token should be valid")
	}
}

func TestRevokeRefreshToken(t *testing.T) {
	svc, _ := newTokenSvc(t)
	user := fakeUser()
	req := httptest.NewRequest("POST", "/", nil)

	raw, _ := svc.IssueRefreshToken(context.Background(), user, req)

	if err := svc.RevokeRefreshToken(context.Background(), raw); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	stored, _ := svc.GetRefreshToken(context.Background(), raw)
	if stored.IsValid() {
		t.Error("token should be invalid after revocation")
	}
}

func TestRotateRefreshToken(t *testing.T) {
	svc, _ := newTokenSvc(t)
	user := fakeUser()
	req := httptest.NewRequest("POST", "/", nil)

	raw, _ := svc.IssueRefreshToken(context.Background(), user, req)

	newRaw, err := svc.RotateRefreshToken(context.Background(), raw, user, req)
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	if newRaw == raw {
		t.Error("new token should differ from old token")
	}

	// Old token should now be revoked
	old, _ := svc.GetRefreshToken(context.Background(), raw)
	if old.IsValid() {
		t.Error("old token should be revoked after rotation")
	}

	// New token should be valid
	newStored, _ := svc.GetRefreshToken(context.Background(), newRaw)
	if newStored == nil || !newStored.IsValid() {
		t.Error("new token should be valid after rotation")
	}
}

func TestRevokeAllUserTokens(t *testing.T) {
	svc, _ := newTokenSvc(t)
	user := fakeUser()
	req := httptest.NewRequest("POST", "/", nil)

	raw1, _ := svc.IssueRefreshToken(context.Background(), user, req)
	raw2, _ := svc.IssueRefreshToken(context.Background(), user, req)

	if err := svc.RevokeAllUserTokens(context.Background(), user.ID); err != nil {
		t.Fatalf("revoke all failed: %v", err)
	}

	t1, _ := svc.GetRefreshToken(context.Background(), raw1)
	t2, _ := svc.GetRefreshToken(context.Background(), raw2)
	if t1.IsValid() || t2.IsValid() {
		t.Error("all tokens should be revoked")
	}
}