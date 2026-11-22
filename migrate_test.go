package goauth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func testMigrateDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:mig_"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestAutoMigrateOnNew(t *testing.T) {
	db := testMigrateDB(t)
	a, err := New(&Config{
		JWTSecret:   "test-secret-at-least-32-chars-long!!",
		DB:          db,
		AutoMigrate: true,
		Providers:   []Provider{&CredentialsProvider{ProviderID: "credentials"}},
		Verification: VerificationOptions{
			OTPSignIn: OTPSignInOptions{Enabled: true},
			FindUser:  func(context.Context, string) (*OAuthUser, error) { return nil, nil },
			Send:      func(context.Context, *VerificationMessage) error { return nil },
		},
		MFA: MFAOptions{TOTP: TOTPOptions{Enabled: true}},
		LoginProtection: LoginProtectionOptions{
			Enabled: true, MaxFailures: 5, LockoutFor: 15 * time.Minute,
		},
		IPAccess: IPAccessOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !a.HasMigrated() {
		t.Fatal("HasMigrated = false after AutoMigrate")
	}
	m := db.Migrator()
	for _, name := range []string{
		"sessions",
		"goauth_verification_tokens",
		"goauth_totp",
		"goauth_login_attempts",
		"goauth_ip_access_rules",
	} {
		if !m.HasTable(name) {
			t.Errorf("missing table %q", name)
		}
	}
	if m.HasTable("users") {
		t.Error("users table must not be created by AutoMigrate")
	}
}

func TestAutoMigrateOffSkipsTables(t *testing.T) {
	db := testMigrateDB(t)
	a, err := New(&Config{
		JWTSecret: "test-secret-at-least-32-chars-long!!",
		DB:        db,
		Providers: []Provider{&CredentialsProvider{ProviderID: "credentials"}},
		MFA:       MFAOptions{TOTP: TOTPOptions{Enabled: true}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.HasMigrated() {
		t.Fatal("HasMigrated = true without AutoMigrate or Migrate")
	}
	if db.Migrator().HasTable("sessions") || db.Migrator().HasTable("goauth_totp") {
		t.Fatal("tables created while AutoMigrate was off")
	}
}

func TestMigrateOnlyEnabledFeatureTables(t *testing.T) {
	db := testMigrateDB(t)
	a, err := New(&Config{
		JWTSecret:   "test-secret-at-least-32-chars-long!!",
		DB:          db,
		AutoMigrate: true,
		Providers:   []Provider{&CredentialsProvider{ProviderID: "credentials"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m := db.Migrator()
	if !m.HasTable("sessions") {
		t.Fatal("sessions should always migrate")
	}
	for _, name := range []string{
		"goauth_verification_tokens",
		"goauth_totp",
		"goauth_login_attempts",
		"goauth_ip_access_rules",
	} {
		if m.HasTable(name) {
			t.Errorf("disabled feature table %q should not be created", name)
		}
	}
	if !a.HasMigrated() {
		t.Fatal("HasMigrated should be true when only sessions is required")
	}
}

func TestMigrateIdempotent(t *testing.T) {
	db := testMigrateDB(t)
	a, err := New(&Config{
		JWTSecret:   "test-secret-at-least-32-chars-long!!",
		DB:          db,
		AutoMigrate: true,
		Providers:   []Provider{&CredentialsProvider{ProviderID: "credentials"}},
		IPAccess:    IPAccessOptions{Enabled: true, SeedWhitelist: []string{"127.0.0.1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Migrate(context.Background()); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if !a.HasMigrated() {
		t.Fatal("HasMigrated = false after second Migrate")
	}
}

func TestModelTableNamesUsePrefix(t *testing.T) {
	cases := map[string]string{
		VerificationToken{}.TableName(): "goauth_verification_tokens",
		TotpFactor{}.TableName():        "goauth_totp",
		LoginAttempt{}.TableName():      "goauth_login_attempts",
		IPEntry{}.TableName():           "goauth_ip_access_rules",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("TableName = %q, want %q", got, want)
		}
	}
}
