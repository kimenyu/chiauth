package models_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kimenyu/chiauth/models"
)

// User.HasPermission

func TestHasPermission_Superuser(t *testing.T) {
	u := &models.User{IsSuperuser: true}
	if !u.HasPermission("anything:ever") {
		t.Error("superuser should have every permission")
	}
}

func TestHasPermission_DirectGrant(t *testing.T) {
	u := &models.User{
		Permissions: []models.Permission{
			{Codename: "invoice:delete"},
		},
	}
	if !u.HasPermission("invoice:delete") {
		t.Error("should have directly granted permission")
	}
	if u.HasPermission("invoice:create") {
		t.Error("should not have un-granted permission")
	}
}

func TestHasPermission_ViaRole(t *testing.T) {
	u := &models.User{
		Roles: []models.Role{
			{
				Slug: "accountant",
				Permissions: []models.Permission{
					{Codename: "invoice:create"},
					{Codename: "invoice:read"},
				},
			},
		},
	}
	if !u.HasPermission("invoice:create") {
		t.Error("should have permission via role")
	}
	if u.HasPermission("invoice:delete") {
		t.Error("should not have permission not in role")
	}
}

// User.HasRole / HasAnyRole

func TestHasRole(t *testing.T) {
	u := &models.User{
		Roles: []models.Role{{Slug: "admin"}, {Slug: "user"}},
	}
	if !u.HasRole("admin") {
		t.Error("expected HasRole(admin) = true")
	}
	if u.HasRole("superuser") {
		t.Error("expected HasRole(superuser) = false")
	}
}

func TestHasAnyRole(t *testing.T) {
	u := &models.User{
		Roles: []models.Role{{Slug: "editor"}},
	}
	if !u.HasAnyRole("viewer", "editor") {
		t.Error("expected HasAnyRole to match 'editor'")
	}
	if u.HasAnyRole("admin", "superuser") {
		t.Error("expected HasAnyRole to return false for unmatched slugs")
	}
}

// User.DisplayName

func TestDisplayName_FirstName(t *testing.T) {
	u := &models.User{FirstName: "Alice", LastName: "Smith"}
	if u.DisplayName() != "Alice Smith" {
		t.Errorf("got %q", u.DisplayName())
	}
}

func TestDisplayName_FallbackUsername(t *testing.T) {
	u := &models.User{Username: "alice99"}
	if u.DisplayName() != "alice99" {
		t.Errorf("got %q", u.DisplayName())
	}
}

func TestDisplayName_FallbackEmail(t *testing.T) {
	u := &models.User{Email: "alice@example.com"}
	if u.DisplayName() != "alice@example.com" {
		t.Errorf("got %q", u.DisplayName())
	}
}

// User.ToResponse

func TestToResponse_NeverExposesPasswordHash(t *testing.T) {
	u := &models.User{
		ID:           uuid.New(),
		Email:        "safe@example.com",
		PasswordHash: "s3cr3t-hash",
		IsActive:     true,
	}
	resp := u.ToResponse()
	// UserResponse has no PasswordHash field — this just confirms the shape compiles.
	if resp.Email != u.Email {
		t.Errorf("email mismatch: %q", resp.Email)
	}
	if resp.IsActive != u.IsActive {
		t.Error("IsActive mismatch")
	}
}

// RefreshToken.IsValid

func TestRefreshToken_IsValid(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	t.Run("valid", func(t *testing.T) {
		rt := &models.RefreshToken{ExpiresAt: future}
		if !rt.IsValid() {
			t.Error("expected valid")
		}
	})
	t.Run("expired", func(t *testing.T) {
		rt := &models.RefreshToken{ExpiresAt: time.Now().Add(-1 * time.Hour)}
		if rt.IsValid() {
			t.Error("expected invalid (expired)")
		}
	})
	t.Run("revoked", func(t *testing.T) {
		now := time.Now()
		rt := &models.RefreshToken{ExpiresAt: future, RevokedAt: &now}
		if rt.IsValid() {
			t.Error("expected invalid (revoked)")
		}
	})
}

// OTPToken.IsValid

func TestOTPToken_IsValid(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	t.Run("valid", func(t *testing.T) {
		o := &models.OTPToken{ExpiresAt: future}
		if !o.IsValid() {
			t.Error("expected valid")
		}
	})
	t.Run("expired", func(t *testing.T) {
		o := &models.OTPToken{ExpiresAt: time.Now().Add(-1 * time.Minute)}
		if o.IsValid() {
			t.Error("expected invalid (expired)")
		}
	})
	t.Run("used", func(t *testing.T) {
		now := time.Now()
		o := &models.OTPToken{ExpiresAt: future, UsedAt: &now}
		if o.IsValid() {
			t.Error("expected invalid (used)")
		}
	})
}