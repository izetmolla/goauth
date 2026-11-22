package goauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func testLoginProtectionAuth(t *testing.T, maxFails int, lockout time.Duration) *Authorization {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:lp_"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(&Config{
		JWTSecret: "test-secret-at-least-32-chars-long!!",
		AuthURL:   "http://localhost",
		DB:        db,
		UI:        UIOptions{EnableAllUI: true, SignInEndpoint: "/sign-in"},
		Providers: []Provider{&CredentialsProvider{
			ProviderID:  "credentials",
			DisplayName: "Email",
			Authorize: func(_ context.Context, values map[string]string, _ *http.Request) (*OAuthUser, error) {
				if values["password"] == "good" {
					return &OAuthUser{ID: "u1", Email: values["email"]}, nil
				}
				return nil, &CredentialsError{Field: "password", Message: "Incorrect password."}
			},
		}},
		LoginProtection: LoginProtectionOptions{
			Enabled:     true,
			MaxFailures: maxFails,
			LockoutFor:  lockout,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.MigrateLoginAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestLoginProtectionRequiresOptions(t *testing.T) {
	if _, err := newLoginProtection(LoginProtectionOptions{Enabled: true}); err == nil {
		t.Fatal("expected error when MaxFailures/LockoutFor missing")
	}
	if _, err := newLoginProtection(LoginProtectionOptions{
		Enabled: true, MaxFailures: 5, LockoutFor: time.Second,
	}); err == nil {
		t.Fatal("expected error for short lockout")
	}
}

func TestLoginProtectionLocksAfterMaxFailures(t *testing.T) {
	a := testLoginProtectionAuth(t, 3, 15*time.Minute)
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("User-Agent", "goauth-test")
	req.Header.Set("X-Device-MAC", "aa:bb:cc:dd:ee:ff")
	values := map[string]string{"email": "a@x.io", "password": "bad"}

	for i := 0; i < 3; i++ {
		a.recordLoginFailure(ctx, req, values)
	}
	row, err := a.findLoginAttempt(ctx, "a@x.io")
	if err != nil || row == nil {
		t.Fatalf("row=%v err=%v", row, err)
	}
	if row.Attempts != 3 || row.LockedUntil == nil {
		t.Fatalf("attempts=%d locked=%v", row.Attempts, row.LockedUntil)
	}
	if row.IPAddress != "203.0.113.10" || row.MACAddress != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("meta ip=%q mac=%q", row.IPAddress, row.MACAddress)
	}

	rec := httptest.NewRecorder()
	req.Header.Set("Accept", "application/json")
	if !a.checkLoginLockout(rec, req, pageSignIn, values) {
		t.Fatal("expected lockout")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}

	a.clearLoginFailures(ctx, values, req)
	if row, _ := a.findLoginAttempt(ctx, "a@x.io"); row != nil {
		t.Fatal("expected cleared")
	}
}

func TestLoginProtectionDisabledByDefault(t *testing.T) {
	p, err := newLoginProtection(LoginProtectionOptions{})
	if err != nil || p.enabled {
		t.Fatalf("enabled=%v err=%v", p.enabled, err)
	}
}
