package chiauth

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/jmoiron/sqlx"
)

//go:embed store/migrations/*.sql
var migrationFiles embed.FS

// runMigrations applies all *.up.sql files from the embedded migrations directory.
// It creates a simple tracking table (chiauth_migrations) to record which
// migrations have been applied — safe to call on every boot.
func runMigrations(db *sqlx.DB) error {
	// Create migrations tracking table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS chiauth_migrations (
			name       VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	if err != nil {
		return fmt.Errorf("chiauth: could not create migrations table: %w", err)
	}

	// List all embedded up migration files
	entries, err := migrationFiles.ReadDir("store/migrations")
	if err != nil {
		return fmt.Errorf("chiauth: could not read migrations directory: %w", err)
	}

	// Collect and sort .up.sql files
	var upFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			upFiles = append(upFiles, e.Name())
		}
	}
	sort.Strings(upFiles)

	for _, name := range upFiles {
		// Check if already applied
		var count int
		err := db.QueryRow(`SELECT COUNT(*) FROM chiauth_migrations WHERE name = $1`, name).Scan(&count)
		if err != nil {
			return fmt.Errorf("chiauth: migration check failed for %s: %w", name, err)
		}
		if count > 0 {
			continue // already applied
		}

		// Read and execute
		content, err := migrationFiles.ReadFile("store/migrations/" + name)
		if err != nil {
			return fmt.Errorf("chiauth: could not read migration %s: %w", name, err)
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("chiauth: could not begin transaction for %s: %w", name, err)
		}

		if _, err := tx.Exec(string(content)); err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("chiauth: migration %s failed: %w", name, err)
		}

		if _, err := tx.Exec(`INSERT INTO chiauth_migrations (name) VALUES ($1)`, name); err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("chiauth: could not record migration %s: %w", name, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("chiauth: could not commit migration %s: %w", name, err)
		}

		fmt.Printf("[chiauth] applied migration: %s\n", name)
	}

	return nil
}
