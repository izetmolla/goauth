package goauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"uuid"

	"gorm.io/gorm"
)

const (
	defaultLoginAttemptTable = "login_attempts"

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
	// TableName of the login_attempts table. Default "login_attempts".
	TableName string
}

// LoginAttempt is one row of the login_attempts table: the current failed
// credentials streak for an email/phone (or IP when no identifier is known),
// plus the last observed client metadata.
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

type loginProtection struct {
	enabled    bool
	maxFails   int
	lockoutFor time.Duration
	table      string
}

func newLoginProtection(o LoginProtectionOptions) (*loginProtection, error) {
	if !o.Enabled {
		return &loginProtection{}, nil
	}
	if o.MaxFailures < 1 || o.MaxFailures > 100 {
		return nil, errors.New("LoginProtection.MaxFailures must be between 1 and 100 when Enabled")
	}
	if o.LockoutFor < time.Minute || o.LockoutFor > 24*time.Hour {
		return nil, errors.New("LoginProtection.LockoutFor must be between 1 minute and 24 hours when Enabled")
	}
	table := o.TableName
	if table == "" {
		table = defaultLoginAttemptTable
	}
	return &loginProtection{
		enabled:    true,
		maxFails:   o.MaxFailures,
		lockoutFor: o.LockoutFor,
		table:      table,
	}, nil
}

// MigrateLoginAttempts creates or updates the login_attempts table.
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
func credentialsIdentifier(values map[string]string, ip string) string {
	if e := normalizeEmail(values[inputEmail]); e != "" {
		return e
	}
	for _, key := range []string{"phone", "username", "login", "number"} {
		if v := strings.TrimSpace(values[key]); v != "" {
			return strings.ToLower(v)
		}
	}
	if ip != "" {
		return "ip:" + ip
	}
	return ""
}

// clientMAC returns an optional device/MAC hint. Browsers cannot read the
// real NIC MAC; clients may send X-Device-MAC / X-Client-MAC / form "mac"
// when they have a stable device identifier to store alongside attempts.
func clientMAC(r *http.Request, values map[string]string) string {
	for _, h := range []string{"X-Device-MAC", "X-Client-MAC", "X-Device-Id"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			if len(v) > 64 {
				return v[:64]
			}
			return v
		}
	}
	if v := strings.TrimSpace(values["mac"]); v != "" {
		if len(v) > 64 {
			return v[:64]
		}
		return v
	}
	return ""
}

// checkLoginLockout refuses credentials sign-in while the identifier is
// locked. It returns true when the response has already been written.
func (a *Authorization) checkLoginLockout(w http.ResponseWriter, r *http.Request, page string, values map[string]string) bool {
	if a.loginProt == nil || !a.loginProt.enabled {
		return false
	}
	id := credentialsIdentifier(values, clientIP(r))
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

// recordLoginFailure increments the failed-attempt streak for the identifier
// and locks it once MaxFailures is reached.
func (a *Authorization) recordLoginFailure(ctx context.Context, r *http.Request, values map[string]string) {
	if a.loginProt == nil || !a.loginProt.enabled {
		return
	}
	ip := clientIP(r)
	id := credentialsIdentifier(values, ip)
	if id == "" {
		return
	}
	now := time.Now().UTC()
	mac := clientMAC(r, values)
	ua := r.UserAgent()
	if len(ua) > 255 {
		ua = ua[:255]
	}

	row, err := a.findLoginAttempt(ctx, id)
	if err != nil {
		return
	}
	if row == nil {
		row = &LoginAttempt{
			ID:            uuid.NewV4().String(),
			Identifier:    id,
			Attempts:      1,
			IPAddress:     ip,
			MACAddress:    mac,
			UserAgent:     ua,
			LastAttemptAt: now,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		if row.Attempts >= a.loginProt.maxFails {
			until := now.Add(a.loginProt.lockoutFor)
			row.LockedUntil = &until
		}
		_ = a.loginAttemptTable(ctx).Create(row).Error
		return
	}

	// Lockout window elapsed: start a fresh streak.
	if row.LockedUntil != nil && !now.Before(row.LockedUntil.UTC()) {
		row.Attempts = 0
		row.LockedUntil = nil
	}
	row.Attempts++
	row.IPAddress = ip
	row.MACAddress = mac
	row.UserAgent = ua
	row.LastAttemptAt = now
	row.UpdatedAt = now
	if row.Attempts >= a.loginProt.maxFails {
		until := now.Add(a.loginProt.lockoutFor)
		row.LockedUntil = &until
	}
	_ = a.loginAttemptTable(ctx).Save(row).Error
}

// clearLoginFailures resets the streak after a successful sign-in.
func (a *Authorization) clearLoginFailures(ctx context.Context, values map[string]string, r *http.Request) {
	if a.loginProt == nil || !a.loginProt.enabled {
		return
	}
	id := credentialsIdentifier(values, clientIP(r))
	if id == "" {
		return
	}
	_ = a.loginAttemptTable(ctx).Where("identifier = ?", id).Delete(&LoginAttempt{}).Error
}
