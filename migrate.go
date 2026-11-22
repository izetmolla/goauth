package goauth

import (
	"context"
	"fmt"
)

// MigrateSessions creates or updates the sessions table with GORM
// AutoMigrate. The users table is never migrated: your app owns that schema.
func (a *Authorization) MigrateSessions(ctx context.Context) error {
	if a == nil || a.db == nil {
		return ErrNotInitialized
	}
	return a.db.WithContext(ctx).Table(a.sessionsTable()).AutoMigrate(&Session{})
}

// Migrate creates or updates every table goauth manages for the current
// configuration: the sessions table, plus each enabled feature table
// (verification tokens, TOTP, login attempts, IP access rules). It is
// idempotent — GORM AutoMigrate creates missing tables and adds missing
// columns. The users table is never touched.
//
// Prefer Config.AutoMigrate so New runs this once at startup. You can also
// call Migrate yourself from a migration job.
func (a *Authorization) Migrate(ctx context.Context) error {
	if a == nil || a.db == nil {
		return ErrNotInitialized
	}
	if err := a.MigrateSessions(ctx); err != nil {
		return fmt.Errorf("sessions: %w", err)
	}
	if a.verify != nil && a.verify.anyEnabled() {
		if err := a.MigrateVerificationTokens(ctx); err != nil {
			return fmt.Errorf("verification tokens: %w", err)
		}
	}
	if a.totpEnabled() {
		if err := a.MigrateTOTP(ctx); err != nil {
			return fmt.Errorf("totp: %w", err)
		}
	}
	if err := a.MigrateLoginAttempts(ctx); err != nil {
		return fmt.Errorf("login attempts: %w", err)
	}
	if err := a.MigrateIPAccess(ctx); err != nil {
		return fmt.Errorf("ip access: %w", err)
	}
	return nil
}

// HasMigrated reports whether every table goauth would create for the
// current configuration already exists. Missing columns are not detected;
// use Migrate (or Config.AutoMigrate) to bring the schema up to date.
func (a *Authorization) HasMigrated() bool {
	if a == nil || a.db == nil {
		return false
	}
	m := a.db.Migrator()
	if !m.HasTable(a.sessionsTable()) {
		return false
	}
	if a.verify != nil && a.verify.anyEnabled() && !m.HasTable(a.verify.table) {
		return false
	}
	if a.totpEnabled() && !m.HasTable(a.totp.table) {
		return false
	}
	if a.loginProt != nil && a.loginProt.enabled && !m.HasTable(a.loginProt.table) {
		return false
	}
	if a.ipAccess != nil && a.ipAccess.enabled && !m.HasTable(a.ipAccess.table) {
		return false
	}
	return true
}
