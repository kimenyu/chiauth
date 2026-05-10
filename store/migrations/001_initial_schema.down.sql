-- chiauth migration: 001_initial_schema.down.sql
DROP TABLE IF EXISTS chiauth_audit_logs;
DROP TABLE IF EXISTS chiauth_otp_tokens;
DROP TABLE IF EXISTS chiauth_refresh_tokens;
DROP TABLE IF EXISTS chiauth_user_permissions;
DROP TABLE IF EXISTS chiauth_user_roles;
DROP TABLE IF EXISTS chiauth_users;
DROP TABLE IF EXISTS chiauth_role_permissions;
DROP TABLE IF EXISTS chiauth_roles;
DROP TABLE IF EXISTS chiauth_permissions;
