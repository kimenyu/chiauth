# chiauth

A complete, mountable authentication and authorization package for Go applications using the [Chi](https://github.com/go-chi/chi) router.

Inspired by [Djoser](https://djoser.readthedocs.io/) for Django REST Framework — drop it into any Chi app and get a full auth system with one function call.

```
go get github.com/kimenyu/chiauth
```

---

## What you get out of the box

| Feature | Detail |
|---|---|
| Registration | Email + password, bcrypt hashing |
| Email verification | OTP token, sent via email or printed to stdout in dev |
| Login | Returns JWT access token + refresh token |
| Token refresh | Rotation — old token revoked on each use |
| Logout | Single session or all sessions |
| Password management | Change, forgot, reset via token |
| Profile | GET / PATCH / DELETE `/me` |
| RBAC | Roles, permissions, middleware gates |
| Admin endpoints | User management, role/permission assignment |
| Audit log | Every auth event recorded with IP + user agent |
| Account lockout | After N failed login attempts (configurable) |
| Swagger UI | Mounted at `/auth/docs` |
| Migrations | Embedded SQL, applied with one call |

---

## Quick Start

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"

    "github.com/go-chi/chi/v5"
    "github.com/jmoiron/sqlx"
    _ "github.com/lib/pq"
    "github.com/kimenyu/chiauth"
    "github.com/kimenyu/chiauth/models"
)

func main() {
    db, err := sqlx.Connect("postgres", os.Getenv("DATABASE_URL"))
    if err != nil {
        log.Fatal(err)
    }

    ca := chiauth.New(chiauth.Config{
        DB:        db,
        JWTSecret: os.Getenv("JWT_SECRET"),
        BaseURL:   "http://localhost:8080",
        AppName:   "My App",
    })

    // Apply database migrations (run once on startup)
    if err := ca.RunMigrations(); err != nil {
        log.Fatalf("migrations failed: %v", err)
    }

    // Seed your domain permissions (idempotent — safe every boot)
    ca.SeedPermissions(context.Background(), []models.Permission{
        {Resource: "invoice", Action: "create", Codename: "invoice:create", Description: "Create invoices"},
        {Resource: "invoice", Action: "read",   Codename: "invoice:read",   Description: "Read invoices"},
        {Resource: "invoice", Action: "delete", Codename: "invoice:delete", Description: "Delete invoices"},
        {Resource: "report",  Action: "read",   Codename: "report:read",    Description: "View reports"},
    })

    // Seed your domain roles
    ca.SeedRoles(context.Background(), []models.SeedRoleInput{
        {
            Slug:        "accountant",
            Name:        "Accountant",
            Permissions: []string{"invoice:create", "invoice:read", "invoice:delete", "report:read"},
        },
        {
            Slug:        "viewer",
            Name:        "Viewer",
            Permissions: []string{"invoice:read", "report:read"},
        },
    })

    r := chi.NewRouter()

    // Mount chiauth at /auth — all endpoints available under this prefix
    r.Mount("/auth", ca.Router())

    // Protect your own routes using chiauth middleware
    r.With(ca.AuthenticateMiddleware()).Get("/dashboard", dashboardHandler)
    r.With(ca.AuthenticateMiddleware(), ca.RequireRole("accountant")).Post("/invoices", createInvoiceHandler)
    r.With(ca.AuthenticateMiddleware(), ca.RequirePermission("invoice:delete")).Delete("/invoices/{id}", deleteInvoiceHandler)
    r.With(ca.AuthenticateMiddleware(), ca.RequireStaff()).Get("/admin/stats", adminStatsHandler)

    log.Println("listening on :8080")
    http.ListenAndServe(":8080", r)
}
```

---

## Configuration

```go
chiauth.Config{
    // Required
    DB:        db,           // *sqlx.DB
    JWTSecret: "...",        // min 32 chars recommended

    // Token TTLs (optional — defaults shown)
    JWTAccessTTL:  15 * time.Minute,
    JWTRefreshTTL: 7 * 24 * time.Hour,

    // Security (optional — defaults shown)
    PasswordMinLength:   8,
    MaxLoginAttempts:    5,
    RequireEmailVerify:  true,   // set false for API-only apps or dev
    RotateRefreshTokens: true,   // recommended — leave true
    AllowHardDelete:     false,  // true = permanent deletion

    // Email (optional)
    EmailSender:       mySender,       // email.Sender interface — see Email section
    EmailTemplatesDir: "./my-emails",  // optional custom templates directory
    BaseURL:           "https://api.myapp.com",
    AppName:           "My App",
    SupportEmail:      "support@myapp.com",

    // Lifecycle hooks (optional)
    OnUserCreated:    func(u *models.User) { /* sync to CRM */ },
    OnLogin:          func(u *models.User, ip string) { /* analytics */ },
    OnPasswordReset:  func(u *models.User) { /* notify */ },
    OnAccountLocked:  func(u *models.User) { /* alert */ },
    OnAccountDeleted: func(u *models.User) { /* cleanup */ },
}
```

---

## All Endpoints

### Public (no auth required)

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/register` | Register a new user |
| `POST` | `/auth/activate` | Verify email with token |
| `POST` | `/auth/activate/resend` | Resend verification email |
| `POST` | `/auth/login` | Login, get access + refresh tokens |
| `POST` | `/auth/token/refresh` | Refresh access token |
| `POST` | `/auth/password/forgot` | Request password reset email |
| `POST` | `/auth/password/reset/confirm` | Confirm password reset with token |
| `GET`  | `/auth/docs/*` | Swagger UI |

### Authenticated (Bearer token required)

| Method | Path | Description |
|---|---|---|
| `POST`   | `/auth/logout` | Revoke current session |
| `POST`   | `/auth/logout/all` | Revoke all sessions |
| `GET`    | `/auth/me` | Get current user |
| `PATCH`  | `/auth/me` | Update profile |
| `DELETE` | `/auth/me` | Delete account |
| `POST`   | `/auth/password/change` | Change password |

### Admin (staff or superuser required)

| Method | Path | Description |
|---|---|---|
| `GET`    | `/auth/admin/users` | List users (paginated) |
| `POST`   | `/auth/admin/users/{id}/roles` | Assign role to user |
| `DELETE` | `/auth/admin/users/{id}/roles/{roleId}` | Remove role from user |
| `POST`   | `/auth/admin/users/{id}/permissions` | Grant direct permission |
| `DELETE` | `/auth/admin/users/{id}/permissions/{permissionId}` | Revoke direct permission |
| `GET`    | `/auth/admin/roles` | List all roles |
| `POST`   | `/auth/admin/roles` | Create a role |
| `DELETE` | `/auth/admin/roles/{id}` | Delete a role |
| `GET`    | `/auth/admin/permissions` | List all permissions |

---

## Permissions and Roles

chiauth is **domain-agnostic**. It does not ship with predefined permissions. You define permissions that match your application's domain and seed them on startup.

**The mental model:** chiauth is a lock manufacturer. It makes locks, keys, and a key management system. It does not decide which doors you put locks on — that is your building, your rules.

### How permissions are structured

Every permission has three fields:

```go
models.Permission{
    Resource:    "invoice",         // the thing being acted on
    Action:      "delete",          // what is being done
    Codename:    "invoice:delete",  // Resource:Action — used in middleware
    Description: "Delete invoices", // human-readable
}
```

### How roles bundle permissions

```go
// Hospital app
ca.SeedPermissions(ctx, []models.Permission{
    {Resource: "patient",      Action: "read",   Codename: "patient:read"},
    {Resource: "prescription", Action: "create", Codename: "prescription:create"},
    {Resource: "lab_result",   Action: "read",   Codename: "lab_result:read"},
})

ca.SeedRoles(ctx, []models.SeedRoleInput{
    {
        Slug:        "doctor",
        Name:        "Doctor",
        Permissions: []string{"patient:read", "prescription:create", "lab_result:read"},
    },
    {
        Slug:        "receptionist",
        Name:        "Receptionist",
        Permissions: []string{"patient:read"},
    },
})
```

```go
// E-commerce app
ca.SeedPermissions(ctx, []models.Permission{
    {Resource: "product", Action: "create", Codename: "product:create"},
    {Resource: "order",   Action: "refund", Codename: "order:refund"},
})

ca.SeedRoles(ctx, []models.SeedRoleInput{
    {Slug: "vendor",        Permissions: []string{"product:create"}},
    {Slug: "support_agent", Permissions: []string{"order:refund"}},
})
```

The middleware call is **identical** regardless of domain:

```go
r.With(ca.AuthenticateMiddleware(), ca.RequirePermission("prescription:create")).Post("/prescriptions", handler)
r.With(ca.AuthenticateMiddleware(), ca.RequirePermission("order:refund")).Post("/orders/{id}/refund", handler)
```

### Permission resolution order

1. `IsSuperuser = true` → always granted, no checks run
2. User has the permission directly (via `POST /auth/admin/users/{id}/permissions`)
3. User holds a role that has the permission

### Built-in system roles

These are seeded automatically and cannot be deleted:

| Slug | Description |
|---|---|
| `superuser` | Bypasses all permission checks |
| `staff` | Can access `/auth/admin/*` endpoints |
| `user` | Default role assigned to every new user |

---

## Middleware Reference

```go
ca := chiauth.New(cfg)

// Validates Bearer JWT, injects *models.User into context
ca.AuthenticateMiddleware()

// Role gates — chain after AuthenticateMiddleware
ca.RequireRole("admin")
ca.RequireAnyRole("admin", "moderator")

// Permission gate — chain after AuthenticateMiddleware
ca.RequirePermission("invoice:delete")

// Convenience gates
ca.RequireStaff()      // IsStaff or IsSuperuser
ca.RequireSuperuser()  // IsSuperuser only

// Read the injected user in your own handlers
user := middleware.UserFromContext(r.Context())
```

---

## Email Setup

### Development (no setup required)

If no `EmailSender` is configured, chiauth prints all tokens to stdout:

```
========== [chiauth] VERIFICATION EMAIL ==========
To:    user@example.com
Token: a1b2c3d4e5f6...
URL:   http://localhost:8080/auth/activate?token=a1b2c3d4...
==================================================
```

Copy the token and POST it to `/auth/activate`. No email provider needed.

You can also disable email verification entirely:

```go
chiauth.Config{
    RequireEmailVerify: false, // accounts are active immediately
}
```

### Production (SMTP via gomail)

Add `gopkg.in/gomail.v2` to your `go.mod`, then use the built-in `SMTPSender`:

```go
import "github.com/kimenyu/chiauth/email"

sender, err := email.NewSMTPSender(email.SMTPConfig{
    Host:        "smtp.gmail.com",
    Port:        587,
    Username:    os.Getenv("SMTP_USER"),
    Password:    os.Getenv("SMTP_PASS"),
    FromAddress: "noreply@myapp.com",
    FromName:    "My App",
})

chiauth.Config{
    EmailSender: sender,
}
```

### Custom email provider (Resend, SendGrid, etc.)

Implement the `email.Sender` interface:

```go
type Sender interface {
    SendVerification(to string, data VerificationData) error
    SendPasswordReset(to string, data PasswordResetData) error
    SendLoginAlert(to string, data LoginAlertData) error
}
```

Example with Resend:

```go
type ResendSender struct{ client *resend.Client }

func (s *ResendSender) SendVerification(to string, data email.VerificationData) error {
    _, err := s.client.Emails.Send(&resend.SendEmailRequest{
        From:    "noreply@myapp.com",
        To:      []string{to},
        Subject: "Verify your email",
        Html:    buildHTML(data), // your own template rendering
    })
    return err
}
```

### Custom email templates

**Option 1 — Directory override** (recommended for most cases):

Create HTML files with the same names as the defaults:

```
my-templates/
├── verification.html
├── password_reset.html
└── login_alert.html
```

```go
sender, _ := email.NewSMTPSender(email.SMTPConfig{
    TemplatesDir: "./my-templates",
    // ...
})
```

**Option 2 — Inline string override:**

```go
chiauth.Config{
    EmailTemplates: &config.EmailTemplateOverrides{
        Verification: `<h1>Hi {{.FirstName}}, verify here: {{.VerificationURL}}</h1>`,
    },
}
```

**Available template variables:**

| Variable | Available in |
|---|---|
| `{{.FirstName}}` | All templates |
| `{{.AppName}}` | All templates |
| `{{.SupportEmail}}` | All templates |
| `{{.VerificationURL}}` | verification.html |
| `{{.Token}}` | verification.html, password_reset.html |
| `{{.ExpiresIn}}` | verification.html, password_reset.html |
| `{{.ResetURL}}` | password_reset.html |
| `{{.IPAddress}}` | password_reset.html, login_alert.html |
| `{{.DeviceInfo}}` | login_alert.html |
| `{{.Time}}` | login_alert.html |

---

## Postman Walkthrough

Full auth flow without a frontend:

### 1. Register
```
POST /auth/register
{
    "email": "joe@example.com",
    "password": "secret1234",
    "first_name": "Joe",
    "last_name": "Doe"
}
```

Check your terminal for the verification token.

### 2. Activate
```
POST /auth/activate
{
    "token": "<token from terminal>"
}
```

Or skip entirely by setting `RequireEmailVerify: false`.

### 3. Login
```
POST /auth/login
{
    "email": "joe@example.com",
    "password": "secret1234"
}
```

Response:
```json
{
    "access_token": "eyJ...",
    "refresh_token": "abc123...",
    "token_type": "Bearer",
    "expires_at": "2026-05-10T16:00:00Z",
    "user": { ... }
}
```

### 4. Use protected endpoints

Set header: `Authorization: Bearer eyJ...`

### 5. Refresh when expired
```
POST /auth/token/refresh
{
    "refresh_token": "abc123..."
}
```

---

## Swagger UI

The Swagger UI is mounted at `/auth/docs`. Generate the spec with:

```bash
go install github.com/swaggo/swag/cmd/swag@latest
swag init -g docs/swagger.go -o docs
```

Then open `http://localhost:8080/auth/docs` in your browser.

---

## Database

chiauth prefixes all its tables with `chiauth_` to avoid conflicts with your existing schema:

```
chiauth_users
chiauth_roles
chiauth_permissions
chiauth_role_permissions
chiauth_user_roles
chiauth_user_permissions
chiauth_refresh_tokens
chiauth_otp_tokens
chiauth_audit_logs
chiauth_migrations
```

Apply migrations:

```go
ca := chiauth.New(cfg)
if err := ca.RunMigrations(); err != nil {
    log.Fatal(err)
}
```

---

## Lifecycle Hooks

React to auth events without patching the package:

```go
chiauth.Config{
    OnUserCreated: func(u *models.User) {
        // Sync to Mailchimp, HubSpot, etc.
        crm.CreateContact(u.Email, u.FirstName)
    },

    OnLogin: func(u *models.User, ip string) {
        // Send login alert email, log to analytics
        analytics.Track("login", u.ID.String(), ip)
    },

    OnPasswordReset: func(u *models.User) {
        // Notify security team of password changes
        slack.Notify(fmt.Sprintf("Password reset: %s", u.Email))
    },

    OnAccountLocked: func(u *models.User) {
        // Alert the user via SMS
        sms.Send(u.PhoneNumber, "Your account has been locked. Contact support.")
    },
}
```

---

## Security Notes

- Passwords are hashed with bcrypt (cost 12)
- Refresh tokens are stored as SHA-256 hashes — a leaked database does not expose active sessions
- OTP tokens (email verification, password reset) are also stored as hashes
- Refresh token rotation is on by default — reuse of a revoked token triggers full session invalidation
- `forgot password` always returns 200 regardless of whether the email exists (prevents enumeration)
- All tables are prefixed `chiauth_` — no conflicts with your schema

---

## License

MIT — see [LICENSE](LICENSE)

---

## Author

Built by [Joseph Njoroge](https://github.com/kimenyu) — [njorogekimenyu.online](https://njorogekimenyu.online/)
