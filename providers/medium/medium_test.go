package medium

import (
	"testing"

	"github.com/izetmolla/goauth"
)

func TestNew(t *testing.T) {
	t.Parallel()
	p, ok := New(Options{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}).(*goauth.OAuthProvider)
	if !ok {
		t.Fatalf("New() type = %T, want *goauth.OAuthProvider", New(Options{}))
	}
	if p.ID() != "medium" {
		t.Fatalf("ID() = %q, want %q", p.ID(), "medium")
	}
	if p.Name() != "Medium" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "Medium")
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
	if len(p.Scopes) == 0 {
		t.Fatal("expected default scopes")
	}
	if got, want := len(p.Scopes), len(DefaultScopes); got != want {
		t.Fatalf("len(Scopes) = %d, want %d", got, want)
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
	if p.AuthorizationURL == "" && p.Issuer == "" {
		t.Fatal("expected AuthorizationURL or Issuer")
	}
}

func TestNew_Overrides(t *testing.T) {
	t.Parallel()
	called := false
	custom := func(_ goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
		called = true
		return &goauth.OAuthUser{ID: "custom"}, nil
	}
	p := New(Options{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
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
	u, err := DefaultProfile(goauth.Profile{"data": map[string]any{"id": "md1", "name": "Med Ium", "imageUrl": "https://md/a"}}, goauth.TokenSet{})
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		t.Fatal("nil user")
	}
	if u.ID != "md1" {
		t.Fatalf("ID = %q, want %q", u.ID, "md1")
	}
	if u.Name != "Med Ium" {
		t.Fatalf("Name = %q, want %q", u.Name, "Med Ium")
	}
	if u.Provider != "medium" {
		t.Fatalf("Provider = %q, want %q", u.Provider, "medium")
	}
}
