package goauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func testIPAccessAuth(t *testing.T) *Authorization {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:ip_"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(&Config{
		JWTSecret: "test-secret-at-least-32-chars-long!!",
		AuthURL:   "http://localhost",
		DB:        db,
		UI:        UIOptions{EnableAllUI: true, SignInEndpoint: "/sign-in"},
		Providers: []Provider{&CredentialsProvider{ProviderID: "credentials"}},
		IPAccess: IPAccessOptions{
			Enabled:       true,
			SeedWhitelist: []string{"127.0.0.1"},
			SeedBlacklist: []string{"198.51.100.0/24"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.MigrateIPAccess(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestIPAccessCRUD(t *testing.T) {
	a := testIPAccessAuth(t)
	ctx := context.Background()

	wl, err := a.AddWhitelistIP(ctx, "203.0.113.10", "office")
	if err != nil || wl.CIDR != "203.0.113.10/32" {
		t.Fatalf("add wl: %+v err=%v", wl, err)
	}
	label := "office-vpn"
	enabled := false
	wl, err = a.UpdateWhitelistIP(ctx, wl.ID, IPEntryUpdate{Label: &label, Enabled: &enabled})
	if err != nil || wl.Label != "office-vpn" || wl.Enabled {
		t.Fatalf("update wl: %+v err=%v", wl, err)
	}
	list, err := a.ListWhitelistIPs(ctx)
	if err != nil || len(list) < 2 { // seed 127.0.0.1 + added
		t.Fatalf("list wl len=%d err=%v", len(list), err)
	}
	if err := a.RemoveWhitelistIP(ctx, wl.ID); err != nil {
		t.Fatal(err)
	}

	bl, err := a.AddBlacklistIP(ctx, "203.0.113.50", "bad")
	if err != nil {
		t.Fatal(err)
	}
	cidr := "203.0.113.50/32"
	bl, err = a.UpdateBlacklistIP(ctx, bl.ID, IPEntryUpdate{CIDR: &cidr})
	if err != nil || bl.CIDR != cidr {
		t.Fatalf("update bl: %+v err=%v", bl, err)
	}
	if err := a.RemoveBlacklistIP(ctx, bl.ID); err != nil {
		t.Fatal(err)
	}
}

func TestIPAccessEnforcement(t *testing.T) {
	a := testIPAccessAuth(t)
	ctx := context.Background()

	// Seed blacklist 198.51.100.0/24
	ok, err := a.allowClientIP(ctx, "198.51.100.20")
	if err != nil || ok {
		t.Fatalf("blacklisted should deny: ok=%v err=%v", ok, err)
	}

	// Whitelist has 127.0.0.1 enabled → others denied
	ok, err = a.allowClientIP(ctx, "8.8.8.8")
	if err != nil || ok {
		t.Fatalf("non-whitelist should deny: ok=%v err=%v", ok, err)
	}
	ok, err = a.allowClientIP(ctx, "127.0.0.1")
	if err != nil || !ok {
		t.Fatalf("whitelist should allow: ok=%v err=%v", ok, err)
	}

	h := a.Handler()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+"/csrf", nil)
	req.RemoteAddr = "198.51.100.7:9"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestIPAccessDisabled(t *testing.T) {
	p, err := newIPAccess(IPAccessOptions{}, DefaultTablePrefix)
	if err != nil || p.enabled {
		t.Fatalf("enabled=%v err=%v", p.enabled, err)
	}
}

func TestIPAccessDefaultTableName(t *testing.T) {
	a := testIPAccessAuth(t)
	if a.ipAccess.table != "goauth_ip_access_rules" {
		t.Fatalf("table=%q want goauth_ip_access_rules", a.ipAccess.table)
	}
}
