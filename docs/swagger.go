// Package docs contains the Swagger/OpenAPI specification for chiauth.
//
// Generate with: swag init -g docs/swagger.go -o docs
//
// @title           chiauth API
// @version         1.0
// @description     A complete, mountable authentication and authorization package for Go + Chi.
// @description
// @description     ## Authentication
// @description     All protected endpoints require a Bearer token in the Authorization header:
// @description     `Authorization: Bearer <access_token>`
// @description
// @description     ## Token Lifecycle
// @description     - Access token: short-lived JWT (default 15 min). Stateless — never stored.
// @description     - Refresh token: long-lived opaque token (default 7 days). Stored server-side as a SHA-256 hash.
// @description     - On refresh, the old token is revoked and a new one is issued (rotation).
// @description
// @description     ## Using with Postman (no frontend required)
// @description     1. POST /auth/register — check stdout for the verification token
// @description     2. POST /auth/activate with `{"token": "<from stdout>"}`
// @description     3. POST /auth/login — copy the access_token and refresh_token
// @description     4. Set `Authorization: Bearer <access_token>` header on protected requests
// @description     5. When the access token expires, POST /auth/token/refresh with the refresh_token
//
// @contact.name    Joseph Njoroge
// @contact.url     https://github.com/kimenyu/chiauth
// @contact.email   njorogekimenyu@gmail.com
//
// @license.name    MIT
// @license.url     https://opensource.org/licenses/MIT
//
// @host            localhost:8080
// @BasePath        /auth
//
// @securityDefinitions.apikey BearerAuth
// @in                         header
// @name                       Authorization
// @description                Enter: Bearer <your_access_token>
//
// @tag.name        auth
// @tag.description Core authentication — register, login, logout, token management
//
// @tag.name        profile
// @tag.description Current user profile management
//
// @tag.name        password
// @tag.description Password change and reset flows
//
// @tag.name        admin
// @tag.description Admin-only endpoints for user, role, and permission management (staff or superuser required)
package docs
