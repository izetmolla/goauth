package goauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// A client must not choose its own address with X-Forwarded-For unless the
// request comes through a configured trusted proxy.
func TestTrustedClientIP(t *testing.T) {
	a := newHardeningAuth(t, Config{TrustedProxies: []string{"10.0.0.0/8"}})
	req := func(remote, xff string) *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	cases := []struct {
		name, remote, xff, want string
	}{
		{"direct client ignores header", "198.51.100.7:1", "127.0.0.1", "198.51.100.7"},
		{"trusted proxy honors header", "10.0.0.5:1", "203.0.113.9", "203.0.113.9"},
		{"spoofed left entry is skipped", "10.0.0.5:1", "127.0.0.1, 203.0.113.9", "203.0.113.9"},
		{"chain of trusted proxies", "10.0.0.5:1", "203.0.113.9, 10.1.1.1", "203.0.113.9"},
		{"trusted proxy without header", "10.0.0.5:1", "", "10.0.0.5"},
	}
	for _, tc := range cases {
		if got := a.trustedClientIP(req(tc.remote, tc.xff)); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
	untrusting := newHardeningAuth(t, Config{})
	if got := untrusting.trustedClientIP(req("10.0.0.5:1", "203.0.113.9")); got != "10.0.0.5" {
		t.Errorf("no TrustedProxies: got %s", got)
	}
	if _, err := New(&Config{JWTSecret: hardeningSecret, DB: a.db, TrustedProxies: []string{"not-an-ip"}}); err == nil {
		t.Error("invalid TrustedProxies accepted")
	}
}

// Regression: a blacklisted client could send X-Forwarded-For with a
// whitelisted address and pass the IP check.
func TestIPAccessIgnoresSpoofedForwardedFor(t *testing.T) {
	a := testIPAccessAuth(t)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+"/csrf", nil)
	r.RemoteAddr = "198.51.100.7:9"
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("spoofed header passed: %d", rec.Code)
	}
}

// Rules are cached, but changes made through the API apply at once.
func TestIPAccessCacheInvalidatesOnChange(t *testing.T) {
	a := testIPAccessAuth(t)
	ctx := t.Context()
	if ok, _ := a.allowClientIP(ctx, "8.8.8.8"); ok {
		t.Fatal("8.8.8.8 should be denied by the whitelist")
	}
	if _, err := a.AddWhitelistIP(ctx, "8.8.8.0/24", "dns"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := a.allowClientIP(ctx, "8.8.8.8"); !ok {
		t.Fatal("new whitelist entry not applied")
	}
}

// Regression: failures were counted with read-modify-write, so parallel
// wrong passwords overwrote each other and never reached the limit.
func TestLoginProtectionCountsConcurrentFailures(t *testing.T) {
	a := testLoginProtectionAuth(t, 50, 15*time.Minute)
	values := map[string]string{"email": "a@x.io"}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil)
			a.recordLoginFailure(context.Background(), r, values)
		})
	}
	wg.Wait()
	row, err := a.findLoginAttempt(t.Context(), "a@x.io")
	if err != nil || row == nil || row.Attempts != 20 {
		t.Fatalf("attempts = %v, err = %v; want 20", row, err)
	}
}

// Regression: a User-Agent cut in the middle of a character produced
// invalid UTF-8, which PostgreSQL rejects, so the failure was never stored.
func TestLoginProtectionStoresValidUTF8(t *testing.T) {
	a := testLoginProtectionAuth(t, 3, 15*time.Minute)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	r.Header.Set("User-Agent", strings.Repeat("a", 254)+"é")
	a.recordLoginFailure(t.Context(), r, map[string]string{"email": "a@x.io"})
	row, err := a.findLoginAttempt(t.Context(), "a@x.io")
	if err != nil || row == nil {
		t.Fatalf("row = %v, err = %v", row, err)
	}
	if !utf8.ValidString(row.UserAgent) || len(row.UserAgent) > 255 {
		t.Fatalf("user agent %q (len %d)", row.UserAgent, len(row.UserAgent))
	}
}

func TestNewFeatureTablesArePrefixed(t *testing.T) {
	a := newHardeningAuth(t, Config{
		LoginProtection: LoginProtectionOptions{Enabled: true, MaxFailures: 3, LockoutFor: time.Minute},
		IPAccess:        IPAccessOptions{Enabled: true},
	})
	if a.loginProt.table != "goauth_login_attempts" || a.ipAccess.table != "goauth_ip_access_rules" {
		t.Fatalf("tables: %s, %s", a.loginProt.table, a.ipAccess.table)
	}
}
