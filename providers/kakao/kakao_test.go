package kakao

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
	if p.ID() != "kakao" {
		t.Fatalf("ID() = %q, want %q", p.ID(), "kakao")
	}
	if p.Name() != "Kakao" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "Kakao")
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
	u, err := DefaultProfile(goauth.Profile{"id": float64(5), "kakao_account": map[string]any{"email": "k@aka.o", "profile": map[string]any{"nickname": "Kakao", "profile_image_url": "https://kk/a"}}}, goauth.TokenSet{})
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		t.Fatal("nil user")
	}
	if u.ID != "5" {
		t.Fatalf("ID = %q, want %q", u.ID, "5")
	}
	if u.Email != "k@aka.o" {
		t.Fatalf("Email = %q, want %q", u.Email, "k@aka.o")
	}
	if u.Name != "Kakao" {
		t.Fatalf("Name = %q, want %q", u.Name, "Kakao")
	}
	if u.Provider != "kakao" {
		t.Fatalf("Provider = %q, want %q", u.Provider, "kakao")
	}
}
