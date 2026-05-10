// Package errors defines all typed errors returned by chiauth services.
// Handlers translate these into appropriate HTTP status codes.
package errors

import "errors"

// Sentinel errors — compare with errors.Is()
var (
	ErrUserNotFound          = errors.New("user not found")
	ErrEmailAlreadyExists    = errors.New("email already in use")
	ErrUsernameAlreadyExists = errors.New("username already in use")
	ErrInvalidCredentials    = errors.New("invalid email or password")
	ErrAccountNotActive      = errors.New("account not yet activated — check your email")
	ErrAccountLocked         = errors.New("account locked due to too many failed attempts")
	ErrAccountDeleted        = errors.New("account has been deleted")

	ErrTokenInvalid   = errors.New("token is invalid")
	ErrTokenExpired   = errors.New("token has expired")
	ErrTokenUsed      = errors.New("token has already been used")
	ErrTokenRevoked   = errors.New("token has been revoked")
	ErrTokenNotFound  = errors.New("token not found")

	ErrRoleNotFound       = errors.New("role not found")
	ErrRoleAlreadyExists  = errors.New("role with this slug already exists")
	ErrRoleIsSystem       = errors.New("system roles cannot be deleted")
	ErrRoleAlreadyAssigned = errors.New("user already has this role")

	ErrPermissionNotFound      = errors.New("permission not found")
	ErrPermissionAlreadyExists = errors.New("permission already exists")
	ErrPermissionAlreadyGranted = errors.New("user already has this permission")

	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden — insufficient permissions")

	ErrWeakPassword    = errors.New("password does not meet minimum requirements")
	ErrSamePassword    = errors.New("new password must be different from current password")
	ErrWrongPassword   = errors.New("current password is incorrect")

	ErrEmailSendFailed = errors.New("failed to send email")
)

// ValidationError holds field-level validation failures.
type ValidationError struct {
	Fields map[string]string
}

func (e *ValidationError) Error() string {
	return "validation failed"
}

// NewValidationError constructs a ValidationError from a map of field→message.
func NewValidationError(fields map[string]string) *ValidationError {
	return &ValidationError{Fields: fields}
}
