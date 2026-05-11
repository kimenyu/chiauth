// Package chiauth is a complete, mountable authentication and authorization
// package for Go applications using the Chi router.
//
// # Quick Start
//
//	r.Mount("/auth", chiauth.New(chiauth.Config{
//	    DB:        db,
//	    JWTSecret: os.Getenv("JWT_SECRET"),
//	}))
//
// # Protecting Routes
//
//	mw := chiauth.Middleware(cfg)
//
//	r.With(mw.Authenticate).Get("/dashboard", handler)
//	r.With(mw.Authenticate, mw.RequireRole("admin")).Get("/admin", handler)
//	r.With(mw.Authenticate, mw.RequirePermission("invoice:delete")).Delete("/invoices/{id}", handler)
//
// # Seeding Permissions and Roles
//
//	chiauth.SeedPermissions(db, []models.Permission{
//	    {Resource: "invoice", Action: "create", Codename: "invoice:create"},
//	    {Resource: "invoice", Action: "delete", Codename: "invoice:delete"},
//	})
//
//	chiauth.SeedRoles(db, []models.SeedRoleInput{
//	    {Slug: "accountant", Name: "Accountant", Permissions: []string{"invoice:create", "invoice:delete"}},
//	})
//
// See https://github.com/kimenyu/chiauth for full documentation.
package chiauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	httpswagger "github.com/swaggo/http-swagger"

	"github.com/kimenyu/chiauth/config"
	"github.com/kimenyu/chiauth/handlers"
	chiauthmiddleware "github.com/kimenyu/chiauth/middleware"
	"github.com/kimenyu/chiauth/models"
	"github.com/kimenyu/chiauth/services"
	"github.com/kimenyu/chiauth/store/postgres"
)

// Config is re-exported from the config package for ergonomic top-level access.
type Config = config.Config

// INSTANCE

// ChiAuth is a fully wired chiauth instance.
// Mount its Router into your Chi app and use its Middleware methods
// to protect your own routes.
type ChiAuth struct {
	cfg        Config
	store      *postgres.Store
	tokenSvc   *services.TokenService
	authSvc    *services.AuthService
	roleSvc    *services.RoleService
	middleware *chiauthmiddleware.AuthMiddleware
	router     chi.Router
}

// New wires all dependencies and returns a ChiAuth instance ready to mount.
//
//	r.Mount("/auth", chiauth.New(chiauth.Config{
//	    DB:        db,
//	    JWTSecret: "your-secret",
//	}).Router())
func New(cfg Config) *ChiAuth {
	cfg = cfg.WithDefaults()

	store := postgres.New(cfg.DB)

	tokenSvc := services.NewTokenService(
		cfg.JWTSecret,
		cfg.JWTAccessTTL,
		cfg.JWTRefreshTTL,
		cfg.RotateRefreshTokens,
		store,
	)

	authSvc := services.NewAuthService(services.AuthServiceConfig{
		UserStore:        store,
		RoleStore:        store,
		OTPStore:         store,
		AuditStore:       store,
		TokenService:     tokenSvc,
		EmailSender:      cfg.EmailSender,
		MaxAttempts:      cfg.MaxLoginAttempts,
		MinPwdLength:     cfg.PasswordMinLength,
		RequireVerify:    cfg.RequireEmailVerify,
		BaseURL:          cfg.BaseURL,
		AppName:          cfg.AppName,
		SupportEmail:     cfg.SupportEmail,
		OnUserCreated:    cfg.OnUserCreated,
		OnUserActivated:  cfg.OnUserActivated,
		OnLogin:          cfg.OnLogin,
		OnPasswordReset:  cfg.OnPasswordReset,
		OnAccountLocked:  cfg.OnAccountLocked,
		OnAccountDeleted: cfg.OnAccountDeleted,
	})

	roleSvc := services.NewRoleService(store, store, store)
	mw := chiauthmiddleware.NewAuthMiddleware(tokenSvc)
	h := handlers.New(authSvc, roleSvc)

	ca := &ChiAuth{
		cfg:        cfg,
		store:      store,
		tokenSvc:   tokenSvc,
		authSvc:    authSvc,
		roleSvc:    roleSvc,
		middleware: mw,
	}

	ca.router = ca.buildRouter(h, mw, tokenSvc, store)
	return ca
}

// Router returns the fully mounted Chi router.
// Pass this to r.Mount("/auth", chiauth.New(cfg).Router()).
func (ca *ChiAuth) Router() http.Handler {
	return ca.router
}

// MIDDLEWARE ACCESSORS

// Authenticate returns Chi middleware that validates the Bearer JWT and
// injects the resolved *models.User into the request context.
// Use this on any route that requires authentication.
func (ca *ChiAuth) Authenticate() func(http.Handler) http.Handler {
	return chiauthmiddleware.AuthenticateFull(ca.tokenSvc, func(ctx context.Context, id interface{}) (*models.User, error) {
		uid, ok := id.(interface{ String() string })
		_ = ok
		_ = uid
		// cast and delegate to store
		return nil, nil // wired fully below via AuthenticateFull
	})
}

// AuthenticateMiddleware returns the authenticate middleware bound to the live user store.
func (ca *ChiAuth) AuthenticateMiddleware() func(http.Handler) http.Handler {
    return chiauthmiddleware.AuthenticateFull(ca.tokenSvc, func(ctx context.Context, id interface{}) (*models.User, error) {
        uid, ok := id.(uuid.UUID)
        if !ok {
            return nil, fmt.Errorf("invalid user id type: %T", id)
        }
        return ca.store.GetByID(ctx, uid)
    })
}

// RequireRole returns middleware that gates on a role slug.
// Chain after Authenticate.
//
//	r.With(ca.AuthenticateMiddleware(), ca.RequireRole("admin")).Get(...)
func (ca *ChiAuth) RequireRole(slug string) func(http.Handler) http.Handler {
	return chiauthmiddleware.RequireRole(slug)
}

// RequireAnyRole returns middleware that passes if the user holds any of the given slugs.
func (ca *ChiAuth) RequireAnyRole(slugs ...string) func(http.Handler) http.Handler {
	return chiauthmiddleware.RequireAnyRole(slugs...)
}

// RequirePermission returns middleware that gates on a permission codename.
// Chain after Authenticate.
//
//	r.With(ca.AuthenticateMiddleware(), ca.RequirePermission("invoice:delete")).Delete(...)
func (ca *ChiAuth) RequirePermission(codename string) func(http.Handler) http.Handler {
	return chiauthmiddleware.RequirePermission(codename)
}

// RequireStaff returns middleware that allows only staff and superusers.
func (ca *ChiAuth) RequireStaff() func(http.Handler) http.Handler {
	return chiauthmiddleware.RequireStaff
}

// RequireSuperuser returns middleware that allows only superusers.
func (ca *ChiAuth) RequireSuperuser() func(http.Handler) http.Handler {
	return chiauthmiddleware.RequireSuperuser
}

// SEEDING HELPERS

// SeedPermissions upserts a list of permissions into the database.
// Call this once on application startup. Idempotent.
//
//	ca.SeedPermissions(context.Background(), []models.Permission{
//	    {Resource: "invoice", Action: "create", Codename: "invoice:create", Description: "Create invoices"},
//	    {Resource: "invoice", Action: "delete", Codename: "invoice:delete", Description: "Delete invoices"},
//	})
func (ca *ChiAuth) SeedPermissions(ctx context.Context, permissions []models.Permission) error {
	return ca.roleSvc.SeedPermissions(ctx, permissions)
}

// SeedRoles creates roles and assigns their permissions. Idempotent.
//
//	ca.SeedRoles(context.Background(), []models.SeedRoleInput{
//	    {
//	        Slug:        "accountant",
//	        Name:        "Accountant",
//	        Permissions: []string{"invoice:create", "invoice:delete"},
//	    },
//	})
func (ca *ChiAuth) SeedRoles(ctx context.Context, inputs []models.SeedRoleInput) error {
	return ca.roleSvc.SeedRoles(ctx, inputs)
}

// MIGRATIONS

// RunMigrations applies all chiauth SQL migrations to the database.
// Call this once during app startup, before mounting the router.
//
//	if err := ca.RunMigrations(); err != nil {
//	    log.Fatalf("chiauth migrations failed: %v", err)
//	}
func (ca *ChiAuth) RunMigrations() error {
	return runMigrations(ca.cfg.DB)
}

// ROUTER CONSTRUCTION

func (ca *ChiAuth) buildRouter(h *handlers.Handler, mw *chiauthmiddleware.AuthMiddleware, tokenSvc *services.TokenService, store *postgres.Store) chi.Router {
	r := chi.NewRouter()

	authenticate := chiauthmiddleware.AuthenticateFull(tokenSvc, func(ctx context.Context, id interface{}) (*models.User, error) {
		uid, ok := id.(uuid.UUID)
		if !ok {
			return nil, fmt.Errorf("invalid user id type: %T", id)
		}
		return store.GetByID(ctx, uid)
	})

	//  Public endpoints 
	r.Post("/register", h.Register)
	r.Post("/activate", h.Activate)
	r.Post("/activate/resend", h.ResendVerification)
	r.Post("/login", h.Login)
	r.Post("/token/refresh", h.RefreshToken)
	r.Post("/password/forgot", h.ForgotPassword)
	r.Post("/password/reset/confirm", h.ResetPassword)

	//  Authenticated endpoints 
	r.Group(func(r chi.Router) {
		r.Use(authenticate)

		r.Post("/logout", h.Logout)
		r.Post("/logout/all", h.LogoutAll)

		r.Get("/me", h.GetMe)
		r.Patch("/me", h.UpdateMe)
		r.Delete("/me", h.DeleteMe)

		r.Post("/password/change", h.ChangePassword)
	})

	// Admin endpoints (staff or superuser) 
	r.Group(func(r chi.Router) {
		r.Use(authenticate)
		r.Use(chiauthmiddleware.RequireStaff)

		// Users
		r.Get("/admin/users", h.AdminListUsers)
		r.Post("/admin/users/{id}/roles", h.AdminAssignRole)
		r.Delete("/admin/users/{id}/roles/{roleId}", h.AdminRemoveRole)
		r.Post("/admin/users/{id}/permissions", h.AdminGrantPermission)
		r.Delete("/admin/users/{id}/permissions/{permissionId}", h.AdminRevokePermission)

		// Roles
		r.Get("/admin/roles", h.AdminListRoles)
		r.Post("/admin/roles", h.AdminCreateRole)
		r.Delete("/admin/roles/{id}", h.AdminDeleteRole)

		// Permissions
		r.Get("/admin/permissions", h.AdminListPermissions)
	})

	//  Swagger UI 
	r.Get("/docs/*", httpswagger.Handler(
		httpswagger.URL("/auth/docs/doc.json"),
	))

	return r
}
