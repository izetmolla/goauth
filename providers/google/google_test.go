package google

import (
	"testing"

	"github.com/izetmolla/goauth"
)

func TestNew(t *testing.T) {
	t.Parallel()
	p, ok := New("client-id", "client-secret").(*goauth.OAuthProvider)
	if !ok {
		t.Fatalf("New() type = %T", New("a", "b"))
	}
	if p.ID() != "google" {
		t.Fatalf("ID() = %q", p.ID())
	}
	if p.Name() != "Google" {
		t.Fatalf("Name() = %q", p.Name())
	}
	if p.Type() != goauth.ProviderOIDC {
		t.Fatalf("Type() = %q", p.Type())
	}
	if p.Issuer != "https://accounts.google.com" {
		t.Fatalf("Issuer = %q", p.Issuer)
	}
	if p.ClientID != "client-id" || p.ClientSecret != "client-secret" {
		t.Fatal("client credentials not wired")
	}
	if p.Profile == nil {
		t.Fatal("Profile is nil")
	}
	wantChecks := []goauth.Check{goauth.CheckPKCE, goauth.CheckState, goauth.CheckNonce}
	if len(p.Checks) != len(wantChecks) {
		t.Fatalf("Checks = %#v", p.Checks)
	}
	for i := range wantChecks {
		if p.Checks[i] != wantChecks[i] {
			t.Fatalf("Checks = %#v", p.Checks)
		}
	}
	wantScopes := []string{"openid", "email", "profile"}
	if len(p.Scopes) != len(wantScopes) {
		t.Fatalf("Scopes = %#v", p.Scopes)
	}
}

func TestProfile(t *testing.T) {
	t.Parallel()
	p := New("id", "secret").(*goauth.OAuthProvider)
	u, err := p.Profile(goauth.Profile{
		"sub": "g-1", "name": "G User", "email": "g@oogle.com", "picture": "https://g/a",
	}, goauth.TokenSet{})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "g-1" || u.Name != "G User" || u.Email != "g@oogle.com" || u.Image != "https://g/a" {
		t.Fatalf("got %#v", u)
	}
}
