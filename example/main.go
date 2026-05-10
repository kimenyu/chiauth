// This file is a complete example showing how to use chiauth in a real application.
// It is NOT part of the chiauth package itself — copy it into your own project.
//
// Run: go run example/main.go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/kimenyu/chiauth"
	chiauthmiddleware "github.com/kimenyu/chiauth/middleware"
	"github.com/kimenyu/chiauth/models"
)

func main() {
	//  Database
	db, err := sqlx.Connect("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	defer db.Close()

	//  chiauth setup 
	ca := chiauth.New(chiauth.Config{
		DB:        db,
		JWTSecret: os.Getenv("JWT_SECRET"), // at least 32 random chars

		// Token lifetimes
		JWTAccessTTL:  15 * time.Minute,
		JWTRefreshTTL: 7 * 24 * time.Hour,

		// Security
		PasswordMinLength:   8,
		MaxLoginAttempts:    5,
		RequireEmailVerify:  false, // set true in production with an EmailSender configured
		RotateRefreshTokens: true,

		// App info (used in emails)
		BaseURL:      "http://localhost:8080",
		AppName:      "Invoice Manager",
		SupportEmail: "hello@njorogekimenyu.online",

		// No EmailSender configured → tokens printed to stdout (dev mode)

		// Hooks
		OnUserCreated: func(u *models.User) {
			log.Printf("[hook] new user registered: %s", u.Email)
		},
		OnLogin: func(u *models.User, ip string) {
			log.Printf("[hook] login: %s from %s", u.Email, ip)
		},
	})

	// Apply migrations (idempotent)
	if err := ca.RunMigrations(); err != nil {
		log.Fatalf("migrations: %v", err)
	}

	// Seed permissions for THIS application's domain (not part of chiauth)
	ctx := context.Background()
	if err := ca.SeedPermissions(ctx, []models.Permission{
		{Resource: "invoice", Action: "create", Codename: "invoice:create", Description: "Create invoices"},
		{Resource: "invoice", Action: "read",   Codename: "invoice:read",   Description: "Read invoices"},
		{Resource: "invoice", Action: "update", Codename: "invoice:update", Description: "Update invoices"},
		{Resource: "invoice", Action: "delete", Codename: "invoice:delete", Description: "Delete invoices"},
		{Resource: "report",  Action: "read",   Codename: "report:read",    Description: "View financial reports"},
		{Resource: "client",  Action: "create", Codename: "client:create",  Description: "Add clients"},
		{Resource: "client",  Action: "read",   Codename: "client:read",    Description: "View clients"},
	}); err != nil {
		log.Fatalf("seed permissions: %v", err)
	}

	// Seed roles for THIS application
	if err := ca.SeedRoles(ctx, []models.SeedRoleInput{
		{
			Slug:        "accountant",
			Name:        "Accountant",
			Description: "Full invoice and client access",
			Permissions: []string{
				"invoice:create", "invoice:read", "invoice:update", "invoice:delete",
				"client:create", "client:read",
				"report:read",
			},
		},
		{
			Slug:        "viewer",
			Name:        "Viewer",
			Description: "Read-only access",
			Permissions: []string{"invoice:read", "client:read", "report:read"},
		},
		{
			Slug:        "billing",
			Name:        "Billing Agent",
			Description: "Can create and send invoices but not delete",
			Permissions: []string{"invoice:create", "invoice:read", "invoice:update", "client:read"},
		},
	}); err != nil {
		log.Fatalf("seed roles: %v", err)
	}

	// Router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Mount all chiauth endpoints under /auth
	r.Mount("/auth", ca.Router())

	//  Your own protected routes
	auth := ca.AuthenticateMiddleware()

	// Any authenticated user
	r.With(auth).Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		user := chiauthmiddleware.UserFromContext(r.Context())
		w.Write([]byte("Welcome " + user.DisplayName()))
	})

	// Only users with invoice:read permission
	r.With(auth, ca.RequirePermission("invoice:read")).Get("/invoices", listInvoicesHandler)

	// Only users with invoice:create permission
	r.With(auth, ca.RequirePermission("invoice:create")).Post("/invoices", createInvoiceHandler)

	// Only users with invoice:delete permission
	r.With(auth, ca.RequirePermission("invoice:delete")).Delete("/invoices/{id}", deleteInvoiceHandler)

	// Only accountants or admins
	r.With(auth, ca.RequireAnyRole("accountant", "admin")).Get("/reports", reportsHandler)

	// Only staff (admin panel)
	r.With(auth, ca.RequireStaff()).Get("/admin/dashboard", adminDashboardHandler)

	log.Println("chiauth example running on :8080")
	log.Println("Swagger UI: http://localhost:8080/auth/docs")
	log.Println("")
	log.Println("Quick Postman flow:")
	log.Println("  1. POST /auth/register")
	log.Println("  2. POST /auth/activate  (copy token from stdout)")
	log.Println("  3. POST /auth/login     (copy access_token)")
	log.Println("  4. GET  /dashboard      (set Authorization: Bearer <token>)")
	http.ListenAndServe(":8080", r)
}

func listInvoicesHandler(w http.ResponseWriter, r *http.Request)  { w.Write([]byte(`{"invoices":[]}`)) }
func createInvoiceHandler(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"message":"invoice created"}`)) }
func deleteInvoiceHandler(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"message":"invoice deleted"}`)) }
func reportsHandler(w http.ResponseWriter, r *http.Request)       { w.Write([]byte(`{"report":{}}`)) }
func adminDashboardHandler(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"admin":true}`)) }
