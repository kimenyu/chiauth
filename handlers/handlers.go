// Package handlers provides Chi HTTP handlers for all chiauth endpoints.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	autherrors "github.com/kimenyu/chiauth/errors"
	"github.com/kimenyu/chiauth/middleware"
	"github.com/kimenyu/chiauth/models"
	"github.com/kimenyu/chiauth/services"
)

// Handler holds all handler dependencies.
type Handler struct {
	authSvc *services.AuthService
	roleSvc *services.RoleService
}

// New creates a Handler.
func New(authSvc *services.AuthService, roleSvc *services.RoleService) *Handler {
	return &Handler{authSvc: authSvc, roleSvc: roleSvc}
}

// REGISTRATION

// Register godoc
// @Summary      Register a new user
// @Description  Creates a new user account. If email verification is enabled, sends a verification email.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body models.RegisterRequest true "Registration payload"
// @Success      201  {object} models.UserResponse
// @Failure      400  {object} models.ErrorResponse
// @Failure      409  {object} models.ErrorResponse "Email already in use"
// @Router       /auth/register [post]
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user, err := h.authSvc.Register(r.Context(), req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, user.ToResponse(), http.StatusCreated)
}

// EMAIL VERIFICATION

// Activate godoc
// @Summary      Verify email address
// @Description  Activates a user account using the token sent to their email. Postman users: copy the token from the email/stdout and POST it here.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body models.ActivateRequest true "Verification token"
// @Success      200  {object} models.UserResponse
// @Failure      400  {object} models.ErrorResponse "Invalid or expired token"
// @Router       /auth/activate [post]
func (h *Handler) Activate(w http.ResponseWriter, r *http.Request) {
	var req models.ActivateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user, err := h.authSvc.ActivateAccount(r.Context(), req.Token)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, user.ToResponse(), http.StatusOK)
}

// ResendVerification godoc
// @Summary      Resend verification email
// @Description  Sends a new verification email. Always returns 200 to prevent email enumeration.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body models.ForgotPasswordRequest true "Email address"
// @Success      200  {object} models.MessageResponse
// @Router       /auth/activate/resend [post]
func (h *Handler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	var req models.ForgotPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	_ = h.authSvc.ResendVerification(r.Context(), req.Email)
	writeJSON(w, models.MessageResponse{Message: "if that email exists and is unverified, a new verification email has been sent"}, http.StatusOK)
}

// LOGIN / LOGOUT

// Login godoc
// @Summary      Login
// @Description  Authenticates a user and returns an access token (15 min) and refresh token (7 days).
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body models.LoginRequest true "Login credentials"
// @Success      200  {object} models.TokenResponse
// @Failure      400  {object} models.ErrorResponse
// @Failure      401  {object} models.ErrorResponse "Invalid credentials"
// @Failure      403  {object} models.ErrorResponse "Account locked or not activated"
// @Router       /auth/login [post]
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	resp, err := h.authSvc.Login(r.Context(), req, r)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// Logout godoc
// @Summary      Logout
// @Description  Revokes the provided refresh token. The access token will expire naturally.
// @Tags         auth
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body body models.RefreshRequest true "Refresh token to revoke"
// @Success      200  {object} models.MessageResponse
// @Failure      401  {object} models.ErrorResponse
// @Router       /auth/logout [post]
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	if user == nil {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req models.RefreshRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	_ = h.authSvc.Logout(r.Context(), req.RefreshToken, user.ID, r)
	writeJSON(w, models.MessageResponse{Message: "logged out successfully"}, http.StatusOK)
}

// LogoutAll godoc
// @Summary      Logout from all devices
// @Description  Revokes all refresh tokens for the authenticated user.
// @Tags         auth
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object} models.MessageResponse
// @Failure      401  {object} models.ErrorResponse
// @Router       /auth/logout/all [post]
func (h *Handler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	if user == nil {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	_ = h.authSvc.LogoutAll(r.Context(), user.ID, r)
	writeJSON(w, models.MessageResponse{Message: "all sessions revoked"}, http.StatusOK)
}

// TOKEN

// RefreshToken godoc
// @Summary      Refresh access token
// @Description  Exchanges a valid refresh token for a new access token. The old refresh token is rotated.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body models.RefreshRequest true "Refresh token"
// @Success      200  {object} models.TokenResponse
// @Failure      401  {object} models.ErrorResponse "Token invalid, expired, or revoked"
// @Router       /auth/token/refresh [post]
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req models.RefreshRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	resp, err := h.authSvc.RefreshTokens(r.Context(), req.RefreshToken, r)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, resp, http.StatusOK)
}

// PROFILE (/me)

// GetMe godoc
// @Summary      Get current user
// @Description  Returns the authenticated user's profile.
// @Tags         profile
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object} models.UserResponse
// @Failure      401  {object} models.ErrorResponse
// @Router       /auth/me [get]
func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	if user == nil {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, user.ToResponse(), http.StatusOK)
}

// UpdateMe godoc
// @Summary      Update profile
// @Description  Updates the authenticated user's profile fields.
// @Tags         profile
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body body models.UpdateProfileRequest true "Profile fields to update"
// @Success      200  {object} models.UserResponse
// @Failure      400  {object} models.ErrorResponse
// @Failure      401  {object} models.ErrorResponse
// @Router       /auth/me [patch]
func (h *Handler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	if user == nil {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req models.UpdateProfileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	updated, err := h.authSvc.UpdateProfile(r.Context(), user.ID, req, r)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, updated.ToResponse(), http.StatusOK)
}

// DeleteMe godoc
// @Summary      Delete account
// @Description  Soft-deletes the authenticated user's account and revokes all sessions.
// @Tags         profile
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object} models.MessageResponse
// @Failure      401  {object} models.ErrorResponse
// @Router       /auth/me [delete]
func (h *Handler) DeleteMe(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	if user == nil {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.authSvc.DeleteAccount(r.Context(), user.ID, false, r); err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, models.MessageResponse{Message: "account deleted"}, http.StatusOK)
}

// PASSWORD

// ChangePassword godoc
// @Summary      Change password
// @Description  Changes the authenticated user's password. Requires current password. Revokes all sessions.
// @Tags         password
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body body models.ChangePasswordRequest true "Current and new password"
// @Success      200  {object} models.MessageResponse
// @Failure      400  {object} models.ErrorResponse
// @Failure      401  {object} models.ErrorResponse
// @Router       /auth/password/change [post]
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	if user == nil {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req models.ChangePasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.authSvc.ChangePassword(r.Context(), user.ID, req, r); err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, models.MessageResponse{Message: "password changed — all sessions revoked"}, http.StatusOK)
}

// ForgotPassword godoc
// @Summary      Request password reset
// @Description  Sends a password reset email. Always returns 200 to prevent email enumeration.
// @Tags         password
// @Accept       json
// @Produce      json
// @Param        body body models.ForgotPasswordRequest true "Email address"
// @Success      200  {object} models.MessageResponse
// @Router       /auth/password/forgot [post]
func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req models.ForgotPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	_ = h.authSvc.ForgotPassword(r.Context(), req.Email, r)
	writeJSON(w, models.MessageResponse{Message: "if that email is registered, a reset link has been sent"}, http.StatusOK)
}

// ResetPassword godoc
// @Summary      Confirm password reset
// @Description  Resets the user's password using the token from the email. Revokes all sessions.
// @Tags         password
// @Accept       json
// @Produce      json
// @Param        body body models.ResetPasswordRequest true "Reset token and new password"
// @Success      200  {object} models.MessageResponse
// @Failure      400  {object} models.ErrorResponse "Invalid or expired token"
// @Router       /auth/password/reset/confirm [post]
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req models.ResetPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.authSvc.ResetPassword(r.Context(), req, r); err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, models.MessageResponse{Message: "password reset successfully"}, http.StatusOK)
}

// ADMIN — USERS

// AdminListUsers godoc
// @Summary      List users (admin)
// @Description  Returns a paginated list of users. Staff or superuser required.
// @Tags         admin
// @Security     BearerAuth
// @Produce      json
// @Param        page      query int    false "Page number (default 1)"
// @Param        page_size query int    false "Page size (default 20)"
// @Param        search    query string false "Search by email or name"
// @Param        is_active query bool   false "Filter by active status"
// @Success      200 {object} models.PaginatedUsers
// @Failure      401 {object} models.ErrorResponse
// @Failure      403 {object} models.ErrorResponse
// @Router       /auth/admin/users [get]
func (h *Handler) AdminListUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	filter := models.UserListFilter{
		Search:   q.Get("search"),
		Page:     page,
		PageSize: pageSize,
	}
	// TODO: store needs to be injected for admin handlers — wired via chiauth.New()
	writeJSON(w, models.MessageResponse{Message: "admin list users — wire store in chiauth.New()"}, http.StatusOK)
	_ = filter
}

// AdminAssignRole godoc
// @Summary      Assign role to user (admin)
// @Description  Assigns a role to a user by role slug.
// @Tags         admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        id   path string true "User ID"
// @Param        body body models.AssignRoleRequest true "Role slug"
// @Success      200  {object} models.MessageResponse
// @Failure      400  {object} models.ErrorResponse
// @Failure      401  {object} models.ErrorResponse
// @Failure      403  {object} models.ErrorResponse
// @Failure      404  {object} models.ErrorResponse
// @Router       /auth/admin/users/{id}/roles [post]
func (h *Handler) AdminAssignRole(w http.ResponseWriter, r *http.Request) {
	actor := middleware.UserFromContext(r.Context())
	if actor == nil {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}
	var req models.AssignRoleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.roleSvc.AssignRoleToUser(r.Context(), targetID, req.RoleSlug, actor.ID); err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, models.MessageResponse{Message: "role assigned"}, http.StatusOK)
}

// AdminRemoveRole godoc
// @Summary      Remove role from user (admin)
// @Tags         admin
// @Security     BearerAuth
// @Produce      json
// @Param        id      path string true "User ID"
// @Param        roleId  path string true "Role ID"
// @Success      200  {object} models.MessageResponse
// @Failure      401  {object} models.ErrorResponse
// @Failure      403  {object} models.ErrorResponse
// @Failure      404  {object} models.ErrorResponse
// @Router       /auth/admin/users/{id}/roles/{roleId} [delete]
func (h *Handler) AdminRemoveRole(w http.ResponseWriter, r *http.Request) {
	actor := middleware.UserFromContext(r.Context())
	if actor == nil {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	targetID, _ := uuid.Parse(chi.URLParam(r, "id"))
	roleID, _ := uuid.Parse(chi.URLParam(r, "roleId"))
	if err := h.roleSvc.RemoveRoleFromUser(r.Context(), targetID, roleID, actor.ID); err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, models.MessageResponse{Message: "role removed"}, http.StatusOK)
}

// AdminGrantPermission godoc
// @Summary      Grant direct permission to user (admin)
// @Tags         admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        id   path string true "User ID"
// @Param        body body models.GrantPermissionRequest true "Permission codename"
// @Success      200  {object} models.MessageResponse
// @Failure      401  {object} models.ErrorResponse
// @Failure      403  {object} models.ErrorResponse
// @Failure      404  {object} models.ErrorResponse
// @Router       /auth/admin/users/{id}/permissions [post]
func (h *Handler) AdminGrantPermission(w http.ResponseWriter, r *http.Request) {
	actor := middleware.UserFromContext(r.Context())
	if actor == nil {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	targetID, _ := uuid.Parse(chi.URLParam(r, "id"))
	var req models.GrantPermissionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.roleSvc.GrantPermissionToUser(r.Context(), targetID, req.Codename, actor.ID); err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, models.MessageResponse{Message: "permission granted"}, http.StatusOK)
}

// AdminRevokePermission godoc
// @Summary      Revoke direct permission from user (admin)
// @Tags         admin
// @Security     BearerAuth
// @Produce      json
// @Param        id           path string true "User ID"
// @Param        permissionId path string true "Permission ID"
// @Success      200  {object} models.MessageResponse
// @Failure      401  {object} models.ErrorResponse
// @Failure      403  {object} models.ErrorResponse
// @Router       /auth/admin/users/{id}/permissions/{permissionId} [delete]
func (h *Handler) AdminRevokePermission(w http.ResponseWriter, r *http.Request) {
	actor := middleware.UserFromContext(r.Context())
	if actor == nil {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	targetID, _ := uuid.Parse(chi.URLParam(r, "id"))
	permID, _ := uuid.Parse(chi.URLParam(r, "permissionId"))
	if err := h.roleSvc.RevokePermissionFromUser(r.Context(), targetID, permID, actor.ID); err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, models.MessageResponse{Message: "permission revoked"}, http.StatusOK)
}

// ADMIN — ROLES

// AdminListRoles godoc
// @Summary      List all roles (admin)
// @Tags         admin
// @Security     BearerAuth
// @Produce      json
// @Success      200 {array}  models.Role
// @Failure      401 {object} models.ErrorResponse
// @Failure      403 {object} models.ErrorResponse
// @Router       /auth/admin/roles [get]
func (h *Handler) AdminListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.roleSvc.ListRoles(r.Context())
	if err != nil {
		writeError(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, roles, http.StatusOK)
}

// AdminCreateRole godoc
// @Summary      Create a role (admin)
// @Tags         admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body body models.CreateRoleRequest true "Role definition"
// @Success      201  {object} models.Role
// @Failure      400  {object} models.ErrorResponse
// @Failure      409  {object} models.ErrorResponse "Slug already exists"
// @Router       /auth/admin/roles [post]
func (h *Handler) AdminCreateRole(w http.ResponseWriter, r *http.Request) {
	var req models.CreateRoleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	role, err := h.roleSvc.CreateRole(r.Context(), req)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, role, http.StatusCreated)
}

// AdminDeleteRole godoc
// @Summary      Delete a role (admin)
// @Description  Deletes a role. System roles (superuser, staff, user) cannot be deleted.
// @Tags         admin
// @Security     BearerAuth
// @Produce      json
// @Param        id path string true "Role ID"
// @Success      200 {object} models.MessageResponse
// @Failure      400 {object} models.ErrorResponse "System role cannot be deleted"
// @Failure      404 {object} models.ErrorResponse
// @Router       /auth/admin/roles/{id} [delete]
func (h *Handler) AdminDeleteRole(w http.ResponseWriter, r *http.Request) {
	roleID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, "invalid role ID", http.StatusBadRequest)
		return
	}
	if err := h.roleSvc.DeleteRole(r.Context(), roleID); err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, models.MessageResponse{Message: "role deleted"}, http.StatusOK)
}

// AdminListPermissions godoc
// @Summary      List all permissions (admin)
// @Tags         admin
// @Security     BearerAuth
// @Produce      json
// @Success      200 {array}  models.Permission
// @Failure      401 {object} models.ErrorResponse
// @Failure      403 {object} models.ErrorResponse
// @Router       /auth/admin/permissions [get]
func (h *Handler) AdminListPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := h.roleSvc.ListPermissions(r.Context())
	if err != nil {
		writeError(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, perms, http.StatusOK)
}

// HELPERS

func decodeJSON(r *http.Request, dst interface{}) error {
	return json.NewDecoder(r.Body).Decode(dst)
}

func writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data) //nolint:errcheck
}

func writeError(w http.ResponseWriter, msg string, status int) {
	writeJSON(w, models.ErrorResponse{Error: msg}, status)
}

func handleServiceError(w http.ResponseWriter, err error) {
	if ve, ok := err.(*autherrors.ValidationError); ok {
		writeJSON(w, models.ErrorResponse{Error: "validation failed", Details: ve.Fields}, http.StatusBadRequest)
		return
	}
	switch err {
	case autherrors.ErrEmailAlreadyExists, autherrors.ErrUsernameAlreadyExists, autherrors.ErrRoleAlreadyExists:
		writeError(w, err.Error(), http.StatusConflict)
	case autherrors.ErrInvalidCredentials, autherrors.ErrUnauthorized:
		writeError(w, err.Error(), http.StatusUnauthorized)
	case autherrors.ErrAccountLocked, autherrors.ErrAccountNotActive, autherrors.ErrForbidden, autherrors.ErrRoleIsSystem:
		writeError(w, err.Error(), http.StatusForbidden)
	case autherrors.ErrUserNotFound, autherrors.ErrRoleNotFound, autherrors.ErrPermissionNotFound, autherrors.ErrTokenNotFound:
		writeError(w, err.Error(), http.StatusNotFound)
	case autherrors.ErrTokenInvalid, autherrors.ErrTokenExpired, autherrors.ErrTokenUsed, autherrors.ErrTokenRevoked:
		writeError(w, err.Error(), http.StatusBadRequest)
	case autherrors.ErrWeakPassword, autherrors.ErrSamePassword, autherrors.ErrWrongPassword:
		writeError(w, err.Error(), http.StatusBadRequest)
	default:
		writeError(w, "internal server error", http.StatusInternalServerError)
	}
}
