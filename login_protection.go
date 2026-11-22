package goauth

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"uuid"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	// loginAttemptTableSuffix follows Config.TablePrefix in the default name
	// (goauth_login_attempts).
	loginAttemptTableSuffix = "login_attempts"

	codeLoginLocked = "LOGIN_LOCKED"
	msgLoginLocked  = "Too many incorrect sign-in attempts. Try again later."
)

// LoginProtectionOptions configures failed-password lockout for credentials
// sign-in. Off by default. When Enabled, MaxFailures and LockoutFor must
// both be set explicitly so operators never inherit silent defaults.
type LoginProtectionOptions struct {
	Enabled bool
	// MaxFailures is how many wrong passwords are allowed before the
	// identifier is locked. Required when Enabled; must be between 1 and 100.
	MaxFailures int
	// LockoutFor is how long the identifier stays locked after MaxFailures.
	// Required when Enabled; must be between 1 minute and 24 hours.
	LockoutFor time.Duration
	// TableName is the GORM table for LoginAttempt rows, used as is. Default
	// Config.TablePrefix + "login_attempts" ("goauth_login_attempts").
	TableName string
}

// LoginAttempt is one row of the goauth-owned login attempts table: the
// current failed credentials streak for an email/phone (or IP when no
// identifier is known), plus the last observed client metadata.
type LoginAttempt struct {
	ID            string     `gorm:"primaryKey;size:36"`
	Identifier    string     `gorm:"size:255;not null;uniqueIndex:idx_goauth_login_attempt_id"`
	Attempts      int        `gorm:"not null"`
	IPAddress     string     `gorm:"size:50"`
	MACAddress    string     `gorm:"size:64"`
	UserAgent     string     `gorm:"size:255"`
	LockedUntil   *time.Time `gorm:"index"`
	LastAttemptAt time.Time  `gorm:"not null"`
	CreatedAt     time.Time  `gorm:"not null"`
	UpdatedAt     time.Time  `gorm:"not null"`
}

// TableName is the default GORM table for LoginAttempt rows
// (DefaultTablePrefix + "login_attempts"). MigrateLoginAttempts and runtime
// queries still honor Config.TablePrefix / LoginProtection.TableName.
func (LoginAttempt) TableName() string {
	return DefaultTablePrefix + loginAttemptTableSuffix
}

type loginProtection struct {
	enabled    bool
	maxFails   int
	lockoutFor time.Duration
	table      string
}

func newLoginProtection(o LoginProtectionOptions, tablePrefix string) (*loginProtection, error) {
	if !o.Enabled {
		return &loginProtection{}, nil
	}
	if o.MaxFailures < 1 || o.MaxFailures > 100 {
		return nil, errors.New("LoginProtection.MaxFailures must be between 1 and 100 when Enabled")
	}
	if o.LockoutFor < time.Minute || o.LockoutFor > 24*time.Hour {
		return nil, errors.New("LoginProtection.LockoutFor must be between 1 minute and 24 hours when Enabled")
	}
	return &loginProtection{
		enabled:    true,
		maxFails:   o.MaxFailures,
		lockoutFor: o.LockoutFor,
		table:      cmp.Or(o.TableName, tablePrefix+loginAttemptTableSuffix),
	}, nil
}

// MigrateLoginAttempts creates or updates the goauth-owned login attempts table.
func (a *Authorization) MigrateLoginAttempts(ctx context.Context) error {
	if a == nil || a.db == nil {
		return ErrNotInitialized
	}
	if a.loginProt == nil || !a.loginProt.enabled {
		return nil
	}
	return a.db.WithContext(ctx).Table(a.loginProt.table).AutoMigrate(&LoginAttempt{})
}

func (a *Authorization) loginAttemptTable(ctx context.Context) *gorm.DB {
	return a.db.WithContext(ctx).Table(a.loginProt.table)
}

// credentialsIdentifier picks the lockout key from the posted form: email
// when present, otherwise phone/username/login, otherwise the client IP.
// It is capped to the column size.
func credentialsIdentifier(values map[string]string, ip string) string {
	if e := normalizeEmail(values[inputEmail]); e != "" {
		return truncateUTF8(e, 255)
	}
	for _, key := range []string{"phone", "username", "login", "number"} {
		if v := strings.TrimSpace(values[key]); v != "" {
			return truncateUTF8(strings.ToLower(v), 255)
		}
	}
	if ip != "" {
		return "ip:" + ip
	}
	return ""
}

// truncateUTF8 shortens s to at most n bytes without splitting a character
// and drops invalid UTF-8, so the value is always storable: PostgreSQL
// rejects invalid UTF-8, and a failed write would silently skip the count.
func truncateUTF8(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}

// clientMAC returns an optional device/MAC hint. Browsers cannot read the
// real NIC MAC; clients may send X-Device-MAC / X-Client-MAC / form "mac"
// when they have a stable device identifier to store alongside attempts.
func clientMAC(r *http.Request, values map[string]string) string {
	for _, h := range []string{"X-Device-MAC", "X-Client-MAC", "X-Device-Id"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			return truncateUTF8(v, 64)
		}
	}
	return truncateUTF8(strings.TrimSpace(values["mac"]), 64)
}

// checkLoginLockout refuses credentials sign-in while the identifier is
// locked. It returns true when the response has already been written.
func (a *Authorization) checkLoginLockout(w http.ResponseWriter, r *http.Request, page string, values map[string]string) bool {
	if a.loginProt == nil || !a.loginProt.enabled {
		return false
	}
	id := credentialsIdentifier(values, a.trustedClientIP(r))
	if id == "" {
		return false
	}
	row, err := a.findLoginAttempt(r.Context(), id)
	if err != nil || row == nil || row.LockedUntil == nil {
		return false
	}
	if time.Now().UTC().Before(row.LockedUntil.UTC()) {
		msg := fmt.Sprintf("%s Try again after %s.", msgLoginLocked, row.LockedUntil.UTC().Format(time.RFC3339))
		a.failure(w, r, page, http.StatusTooManyRequests, codeLoginLocked, msg, inputPassword)
		return true
	}
	return false
}

func (a *Authorization) findLoginAttempt(ctx context.Context, identifier string) (*LoginAttempt, error) {
	var row LoginAttempt
	err := a.loginAttemptTable(ctx).Where("identifier = ?", identifier).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// recordLoginFailure counts one failed sign-in for the identifier and locks
// it once MaxFailures is reached. Every step is a single atomic statement, so
// concurrent wrong passwords are all counted: a read-modify-write would let
// parallel guesses overwrite each other and never reach the limit.
func (a *Authorization) recordLoginFailure(ctx context.Context, r *http.Request, values map[string]string) {
	if a.loginProt == nil || !a.loginProt.enabled {
		return
	}
	ip := a.trustedClientIP(r)
	id := credentialsIdentifier(values, ip)
	if id == "" {
		return
	}
	now := time.Now().UTC()
	byID := func() *gorm.DB { return a.loginAttemptTable(ctx).Where("identifier = ?", id) }

	// Create the streak row; a concurrent insert for the same identifier wins.
	if err := a.loginAttemptTable(ctx).
		Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "identifier"}}, DoNothing: true}).
		Create(&LoginAttempt{
			ID:            uuid.NewV4().String(),
			Identifier:    id,
			LastAttemptAt: now,
			CreatedAt:     now,
			UpdatedAt:     now,
		}).Error; err != nil {
		return
	}
	// A lockout that has run out starts a fresh streak.
	if err := byID().
		Where("locked_until IS NOT NULL AND locked_until <= ?", now).
		Updates(map[string]any{"attempts": 0, "locked_until": nil}).Error; err != nil {
		return
	}
	if err := byID().Updates(map[string]any{
		"attempts":        gorm.Expr("attempts + 1"),
		"ip_address":      truncateUTF8(ip, 50),
		"mac_address":     clientMAC(r, values),
		"user_agent":      truncateUTF8(r.UserAgent(), 255),
		"last_attempt_at": now,
		"updated_at":      now,
	}).Error; err != nil {
		return
	}
	_ = byID().
		Where("attempts >= ? AND locked_until IS NULL", a.loginProt.maxFails).
		Update("locked_until", now.Add(a.loginProt.lockoutFor)).Error
}

// clearLoginFailures resets the streak after a successful sign-in.
func (a *Authorization) clearLoginFailures(ctx context.Context, values map[string]string, r *http.Request) {
	if a.loginProt == nil || !a.loginProt.enabled {
		return
	}
	a.clearLoginFailuresFor(ctx, credentialsIdentifier(values, a.trustedClientIP(r)))
}

// clearLoginFailuresFor resets the streak of one identifier, for example
// after a successful password reset proved control of the email.
func (a *Authorization) clearLoginFailuresFor(ctx context.Context, identifier string) {
	if a.loginProt == nil || !a.loginProt.enabled || identifier == "" {
		return
	}
	_ = a.loginAttemptTable(ctx).Where("identifier = ?", identifier).Delete(&LoginAttempt{}).Error
}
