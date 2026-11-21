package line

import (
	"encoding/base64"
	"encoding/json"
	"github.com/izetmolla/goauth"
	"testing"
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
	if p.ID() != "line" {
		t.Fatalf("ID() = %q, want %q", p.ID(), "line")
	}
	if p.Name() != "LINE" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "LINE")
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
	if p.AuthorizationStyle != "body" {
		t.Fatalf("AuthorizationStyle = %q, want %q", p.AuthorizationStyle, "body")
	}
	if p.AuthorizationURL == "" && p.Issuer == "" {
		t.Fatal("expected AuthorizationURL or Issuer")
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
	u, err := DefaultProfile(goauth.Profile{"userId": "line-1", "displayName": "Line User", "pictureUrl": "https://line/a"}, goauth.TokenSet{IDToken: fakeIDToken(t, map[string]any{"email": "l@ine.com"})})
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		t.Fatal("nil user")
	}
	if u.ID != "line-1" {
		t.Fatalf("ID = %q, want %q", u.ID, "line-1")
	}
	if u.Email != "l@ine.com" {
		t.Fatalf("Email = %q, want %q", u.Email, "l@ine.com")
	}
	if u.Name != "Line User" {
		t.Fatalf("Name = %q, want %q", u.Name, "Line User")
	}
	if u.Provider != "line" {
		t.Fatalf("Provider = %q, want %q", u.Provider, "line")
	}
}

func fakeIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}
