package vk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if p.ID() != "vk" {
		t.Fatalf("ID() = %q, want %q", p.ID(), "vk")
	}
	if p.Name() != "VK" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "VK")
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
	if p.FetchUserInfo == nil {
		t.Fatal("FetchUserInfo is nil")
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
	u, err := DefaultProfile(goauth.Profile{"response": []any{map[string]any{"id": float64(100), "first_name": "V", "last_name": "K", "photo_100": "https://vk/a"}}, "email": "v@k.com"}, goauth.TokenSet{})
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		t.Fatal("nil user")
	}
	if u.ID != "100" {
		t.Fatalf("ID = %q, want %q", u.ID, "100")
	}
	if u.Email != "v@k.com" {
		t.Fatalf("Email = %q, want %q", u.Email, "v@k.com")
	}
	if u.Name != "V K" {
		t.Fatalf("Name = %q, want %q", u.Name, "V K")
	}
	if u.Provider != "vk" {
		t.Fatalf("Provider = %q, want %q", u.Provider, "vk")
	}
}

func TestFetchUserInfo_UsersGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "access_token=tok") {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"response": []any{map[string]any{"id": float64(100), "first_name": "V", "last_name": "K", "photo_100": "https://vk/a"}},
		})
	}))
	t.Cleanup(srv.Close)
	prev := usersAPIURL
	usersAPIURL = srv.URL
	t.Cleanup(func() { usersAPIURL = prev })

	p := New(Options{ClientID: "id", ClientSecret: "secret"}).(*goauth.OAuthProvider)
	profile, err := p.FetchUserInfo(context.Background(), goauth.TokenSet{
		AccessToken: "tok",
		Raw:         map[string]any{"user_id": "100", "email": "v@k.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if profile["email"] != "v@k.com" {
		t.Fatalf("email = %v", profile["email"])
	}
	u, err := DefaultProfile(profile, goauth.TokenSet{Raw: map[string]any{"email": "v@k.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "100" || u.Name != "V K" || u.Email != "v@k.com" {
		t.Fatalf("got %#v", u)
	}
}
