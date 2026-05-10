-- chiauth migration: 001_initial_schema.up.sql
-- Run via chiauth.RunMigrations(db) or apply manually.

-- ─────────────────────────────────────────────
-- PERMISSIONS
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chiauth_permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    codename    VARCHAR(255) UNIQUE NOT NULL,   -- "invoice:delete"
    resource    VARCHAR(100) NOT NULL,           -- "invoice"
    action      VARCHAR(100) NOT NULL,           -- "delete"
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chiauth_permissions_codename ON chiauth_permissions(codename);
CREATE INDEX IF NOT EXISTS idx_chiauth_permissions_resource ON chiauth_permissions(resource);

-- ─────────────────────────────────────────────
-- ROLES
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chiauth_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(100) NOT NULL,
    slug        VARCHAR(100) UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_default  BOOLEAN NOT NULL DEFAULT FALSE,  -- auto-assigned on register
    is_system   BOOLEAN NOT NULL DEFAULT FALSE,  -- cannot be deleted
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chiauth_roles_slug ON chiauth_roles(slug);

-- Seed the three system roles
INSERT INTO chiauth_roles (name, slug, description, is_default, is_system)
VALUES
    ('Superuser', 'superuser', 'Bypasses all permission checks', FALSE, TRUE),
    ('Staff',     'staff',     'Access to admin endpoints',       FALSE, TRUE),
    ('User',      'user',      'Default role for all users',      TRUE,  TRUE)
ON CONFLICT (slug) DO NOTHING;

-- ─────────────────────────────────────────────
-- ROLE <-> PERMISSION
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chiauth_role_permissions (
    role_id       UUID NOT NULL REFERENCES chiauth_roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES chiauth_permissions(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

-- ─────────────────────────────────────────────
-- USERS
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chiauth_users (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 VARCHAR(255) UNIQUE NOT NULL,
    username              VARCHAR(100) UNIQUE,
    password_hash         VARCHAR(255) NOT NULL,
    first_name            VARCHAR(100) NOT NULL DEFAULT '',
    last_name             VARCHAR(100) NOT NULL DEFAULT '',
    phone_number          VARCHAR(30) NOT NULL DEFAULT '',
    avatar_url            TEXT NOT NULL DEFAULT '',

    -- Access control
    is_active             BOOLEAN NOT NULL DEFAULT FALSE,
    is_staff              BOOLEAN NOT NULL DEFAULT FALSE,
    is_superuser          BOOLEAN NOT NULL DEFAULT FALSE,
    is_locked             BOOLEAN NOT NULL DEFAULT FALSE,

    -- Security tracking
    failed_login_attempts INT NOT NULL DEFAULT 0,
    last_login            TIMESTAMPTZ,
    last_login_ip         VARCHAR(45) NOT NULL DEFAULT '',

    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at            TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_chiauth_users_email      ON chiauth_users(LOWER(email));
CREATE INDEX IF NOT EXISTS idx_chiauth_users_username   ON chiauth_users(LOWER(username));
CREATE INDEX IF NOT EXISTS idx_chiauth_users_deleted_at ON chiauth_users(deleted_at);

-- ─────────────────────────────────────────────
-- USER <-> ROLE
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chiauth_user_roles (
    user_id    UUID NOT NULL REFERENCES chiauth_users(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES chiauth_roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- ─────────────────────────────────────────────
-- USER <-> PERMISSION (direct grants)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chiauth_user_permissions (
    user_id       UUID NOT NULL REFERENCES chiauth_users(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES chiauth_permissions(id) ON DELETE CASCADE,
    granted_by    UUID REFERENCES chiauth_users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, permission_id)
);

-- ─────────────────────────────────────────────
-- REFRESH TOKENS
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chiauth_refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES chiauth_users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(255) UNIQUE NOT NULL,  -- SHA-256 of raw token
    device_info VARCHAR(255) NOT NULL DEFAULT '',
    ip_address  VARCHAR(45)  NOT NULL DEFAULT '',
    user_agent  TEXT         NOT NULL DEFAULT '',
    expires_at  TIMESTAMPTZ  NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chiauth_refresh_tokens_user_id    ON chiauth_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_chiauth_refresh_tokens_token_hash ON chiauth_refresh_tokens(token_hash);

-- ─────────────────────────────────────────────
-- OTP TOKENS
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chiauth_otp_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES chiauth_users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    purpose    VARCHAR(50)  NOT NULL,   -- email_verification | password_reset | two_factor
    expires_at TIMESTAMPTZ  NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chiauth_otp_tokens_hash_purpose ON chiauth_otp_tokens(token_hash, purpose);
CREATE INDEX IF NOT EXISTS idx_chiauth_otp_tokens_user_id      ON chiauth_otp_tokens(user_id);

-- ─────────────────────────────────────────────
-- AUDIT LOGS
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chiauth_audit_logs (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID REFERENCES chiauth_users(id) ON DELETE SET NULL,  -- nullable: failed logins
    event      VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45)  NOT NULL DEFAULT '',
    user_agent TEXT         NOT NULL DEFAULT '',
    metadata   JSONB        NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chiauth_audit_logs_user_id   ON chiauth_audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_chiauth_audit_logs_event     ON chiauth_audit_logs(event);
CREATE INDEX IF NOT EXISTS idx_chiauth_audit_logs_created_at ON chiauth_audit_logs(created_at DESC);
