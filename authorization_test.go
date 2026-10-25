package goauth

import (
	"testing"
	"time"

	"gorm.io/gorm"
)

// Regression: New used to read most settings only from the defaults, silently
// ignoring the values set on Config.
func TestNewHonorsConfig(t *testing.T) {
	a, err := New(&Config{
		JWTSecret:            "secret",
		DB:                   &gorm.DB{},
		AccessTokenDuration:  "5m",
		RefreshTokenDuration: "30d",
		UserTableName:        "accounts",
		SessionTableName:     "auth_sessions",
		RedisTTL:             time.Hour,
		CookieSessionName:    "sid",
		SignInRedirectURL:    "/login",
	}, func(c *Config) { c.RedisPrefix = "APP" })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	checks := []struct{ name, got, want string }{
		{"accessTokenDuration", a.accessTokenDuration, "5m"},
		{"refreshTokenDuration", a.refreshTokenDuration, "30d"},
		{"userTableName", a.userTableName, "accounts"},
		{"sessionTableName", a.sessionTableName, "auth_sessions"},
		{"cookieSessionName", a.cookieSessionName, "sid"},
		{"signInRedirectURL", a.signInRedirectURL, "/login"},
		{"redisPrefix (from option)", a.redisPrefix, "APP"},
		{"signingMethod (default)", a.signingMethod, DefaultSigningMethodHMAC},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if a.redisTTL != time.Hour {
		t.Errorf("redisTTL = %v, want %v", a.redisTTL, time.Hour)
	}
}

func TestNewRequiresSecretAndDB(t *testing.T) {
	if _, err := New(&Config{DB: &gorm.DB{}}); err == nil {
		t.Error("New without JWTSecret: want error")
	}
	if _, err := New(&Config{JWTSecret: "secret"}); err == nil {
		t.Error("New without DB: want error")
	}
	if _, err := New(&Config{DB: &gorm.DB{}}, func(c *Config) { c.JWTSecret = "secret" }); err != nil {
		t.Errorf("JWTSecret from option: %v", err)
	}
}
