package services

import (
	"context"

	"github.com/google/uuid"
	autherrors "github.com/kimenyu/chiauth/errors"
	"github.com/kimenyu/chiauth/models"
	"github.com/kimenyu/chiauth/store"
)

// RoleService handles role and permission management.
type RoleService struct {
	roleStore  store.RoleStore
	userStore  store.UserStore
	auditStore store.AuditStore
}

// NewRoleService constructs a RoleService.
func NewRoleService(roleStore store.RoleStore, userStore store.UserStore, auditStore store.AuditStore) *RoleService {
	return &RoleService{
		roleStore:  roleStore,
		userStore:  userStore,
		auditStore: auditStore,
	}
}

// ROLES

// ListRoles returns all roles with their permissions.
func (s *RoleService) ListRoles(ctx context.Context) ([]models.Role, error) {
	return s.roleStore.ListRoles(ctx)
}

// GetRole returns a single role by ID.
func (s *RoleService) GetRole(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	role, err := s.roleStore.GetRoleByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, autherrors.ErrRoleNotFound
	}
	return role, nil
}

// CreateRole creates a new role and optionally assigns permissions by codename.
func (s *RoleService) CreateRole(ctx context.Context, req models.CreateRoleRequest) (*models.Role, error) {
	existing, _ := s.roleStore.GetRoleBySlug(ctx, req.Slug)
	if existing != nil {
		return nil, autherrors.ErrRoleAlreadyExists
	}

	role := &models.Role{
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
	}
	if err := s.roleStore.CreateRole(ctx, role); err != nil {
		return nil, err
	}

	// Assign permissions
	for _, codename := range req.Permissions {
		perm, err := s.roleStore.GetPermissionByCodename(ctx, codename)
		if err != nil || perm == nil {
			continue // skip unknown codenames
		}
		_ = s.roleStore.AssignPermissionToRole(ctx, role.ID, perm.ID)
	}

	return s.roleStore.GetRoleByID(ctx, role.ID)
}

// DeleteRole deletes a role. Fails if the role is a system role.
func (s *RoleService) DeleteRole(ctx context.Context, id uuid.UUID) error {
	role, err := s.roleStore.GetRoleByID(ctx, id)
	if err != nil {
		return err
	}
	if role == nil {
		return autherrors.ErrRoleNotFound
	}
	if role.IsSystem {
		return autherrors.ErrRoleIsSystem
	}
	return s.roleStore.DeleteRole(ctx, id)
}

// PERMISSIONS

// ListPermissions returns all seeded permissions.
func (s *RoleService) ListPermissions(ctx context.Context) ([]models.Permission, error) {
	return s.roleStore.ListPermissions(ctx)
}

// USER ROLE MANAGEMENT (admin)

// AssignRoleToUser assigns a role to a user by role slug.
func (s *RoleService) AssignRoleToUser(ctx context.Context, userID uuid.UUID, roleSlug string, actorID uuid.UUID) error {
	user, err := s.userStore.GetByID(ctx, userID)
	if err != nil || user == nil {
		return autherrors.ErrUserNotFound
	}
	role, err := s.roleStore.GetRoleBySlug(ctx, roleSlug)
	if err != nil || role == nil {
		return autherrors.ErrRoleNotFound
	}
	if user.HasRole(roleSlug) {
		return autherrors.ErrRoleAlreadyAssigned
	}
	if err := s.userStore.AssignRole(ctx, userID, role.ID); err != nil {
		return err
	}
	s.auditStore.Log(ctx, &models.AuditLog{
		UserID: &actorID,
		Event:  models.EventRoleAssigned,
		Metadata: map[string]string{
			"target_user_id": userID.String(),
			"role_slug":      roleSlug,
		},
	})
	return nil
}

// RemoveRoleFromUser removes a role from a user.
func (s *RoleService) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID, actorID uuid.UUID) error {
	role, err := s.roleStore.GetRoleByID(ctx, roleID)
	if err != nil || role == nil {
		return autherrors.ErrRoleNotFound
	}
	if err := s.userStore.RemoveRole(ctx, userID, roleID); err != nil {
		return err
	}
	s.auditStore.Log(ctx, &models.AuditLog{
		UserID: &actorID,
		Event:  models.EventRoleRevoked,
		Metadata: map[string]string{
			"target_user_id": userID.String(),
			"role_id":        roleID.String(),
		},
	})
	return nil
}


// USER DIRECT PERMISSION MANAGEMENT (admin)

// GrantPermissionToUser grants a direct permission to a user.
func (s *RoleService) GrantPermissionToUser(ctx context.Context, userID uuid.UUID, codename string, actorID uuid.UUID) error {
	user, err := s.userStore.GetByID(ctx, userID)
	if err != nil || user == nil {
		return autherrors.ErrUserNotFound
	}
	perm, err := s.roleStore.GetPermissionByCodename(ctx, codename)
	if err != nil || perm == nil {
		return autherrors.ErrPermissionNotFound
	}
	if err := s.userStore.GrantPermission(ctx, userID, perm.ID, actorID); err != nil {
		return err
	}
	s.auditStore.Log(ctx, &models.AuditLog{
		UserID: &actorID,
		Event:  models.EventPermissionGranted,
		Metadata: map[string]string{
			"target_user_id": userID.String(),
			"codename":       codename,
		},
	})
	return nil
}

// RevokePermissionFromUser removes a direct permission from a user.
func (s *RoleService) RevokePermissionFromUser(ctx context.Context, userID, permissionID uuid.UUID, actorID uuid.UUID) error {
	if err := s.userStore.RevokePermission(ctx, userID, permissionID); err != nil {
		return err
	}
	s.auditStore.Log(ctx, &models.AuditLog{
		UserID: &actorID,
		Event:  models.EventPermissionRevoked,
		Metadata: map[string]string{
			"target_user_id": userID.String(),
			"permission_id":  permissionID.String(),
		},
	})
	return nil
}

// SEEDING (called once on app startup)

// SeedPermissions upserts a list of permissions. Idempotent — safe to call on every boot.
func (s *RoleService) SeedPermissions(ctx context.Context, permissions []models.Permission) error {
	for i := range permissions {
		if err := s.roleStore.UpsertPermission(ctx, &permissions[i]); err != nil {
			return err
		}
	}
	return nil
}

// SeedRoles creates roles and assigns their permissions. Idempotent.
func (s *RoleService) SeedRoles(ctx context.Context, inputs []models.SeedRoleInput) error {
	for _, input := range inputs {
		existing, _ := s.roleStore.GetRoleBySlug(ctx, input.Slug)
		var role *models.Role
		if existing == nil {
			role = &models.Role{
				Name:        input.Name,
				Slug:        input.Slug,
				Description: input.Description,
				IsDefault:   input.IsDefault,
				IsSystem:    input.IsSystem,
			}
			if err := s.roleStore.CreateRole(ctx, role); err != nil {
				return err
			}
		} else {
			role = existing
		}
		for _, codename := range input.Permissions {
			perm, err := s.roleStore.GetPermissionByCodename(ctx, codename)
			if err != nil || perm == nil {
				continue
			}
			_ = s.roleStore.AssignPermissionToRole(ctx, role.ID, perm.ID)
		}
	}
	return nil
}
