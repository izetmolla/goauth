package workos

import (
	"github.com/izetmolla/goauth"
	"testing"
)

func TestNew(t *testing.T) {
	t.Parallel()
	p, ok := New(Options{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Issuer:       "https://issuer.example",
		Connection:   "conn_123",
	}).(*goauth.OAuthProvider)
	if !ok {
		t.Fatalf("New() type = %T, want *goauth.OAuthProvider", New(Options{}))
	}
	if p.ID() != "workos" {
		t.Fatalf("ID() = %q, want %q", p.ID(), "workos")
	}
	if p.Name() != "WorkOS" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "WorkOS")
	}
	if p.Type() != goauth.ProviderOAuth {
		t.Fatalf("Type() = %q, want %q", p.Type(), goauth.ProviderOAuth)
	}
	if p.ClientID != "client-id" || p.ClientSecret != "client-secret" {
		t.Fatalf("client credentials not wired: %q / %q", p.ClientID, p.ClientSecret)
	}
	if p.Profile == nil {
		t.Fatal("Profile is nil")
	}
	wantChecks := []goauth.Check{goauth.CheckState}
	if len(p.Checks) != len(wantChecks) {
		t.Fatalf("Checks = %#v, want %#v", p.Checks, wantChecks)
	}
	for i := range wantChecks {
		if p.Checks[i] != wantChecks[i] {
			t.Fatalf("Checks = %#v, want %#v", p.Checks, wantChecks)
		}
	}
	if p.AuthorizationStyle != "body" {
		t.Fatalf("AuthorizationStyle = %q, want %q", p.AuthorizationStyle, "body")
	}
	if p.Issuer == "" && p.AuthorizationURL == "" {
		t.Fatal("expected Issuer or AuthorizationURL")
	}
}

func TestNew_Overrides(t *testing.T) {
	t.Parallel()
	called := false
	custom := func(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
		called = true
		return &goauth.OAuthUser{ID: "custom"}, nil
	}
	p := New(Options{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Issuer:       "https://issuer.example",
		Connection:   "conn_123",
		Scopes:       []string{"custom-scope"},
		Profile:      custom,
	}).(*goauth.OAuthProvider)
	if len(p.Scopes) != 1 || p.Scopes[0] != "custom-scope" {
		t.Fatalf("Scopes = %#v", p.Scopes)
	}
	u, err := p.Profile(goauth.Profile{}, goauth.TokenSet{})
	if err != nil || u.ID != "custom" || !called {
		t.Fatalf("custom profile not used: user=%#v err=%v called=%v", u, err, called)
	}
}

func TestDefaultProfile(t *testing.T) {
	t.Parallel()
	u, err := DefaultProfile(goauth.Profile{"id": "wo1", "first_name": "Work", "last_name": "OS", "email": "w@ork.os", "raw_attributes": map[string]any{"picture": "https://wo/a"}}, goauth.TokenSet{})
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		t.Fatal("nil user")
	}
	if u.ID != "wo1" {
		t.Fatalf("ID = %q, want %q", u.ID, "wo1")
	}
	if u.Email != "w@ork.os" {
		t.Fatalf("Email = %q, want %q", u.Email, "w@ork.os")
	}
	if u.Name != "Work OS" {
		t.Fatalf("Name = %q, want %q", u.Name, "Work OS")
	}
	if u.Provider != "workos" {
		t.Fatalf("Provider = %q, want %q", u.Provider, "workos")
	}
}
