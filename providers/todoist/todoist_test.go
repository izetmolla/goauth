package todoist

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	if p.ID() != "todoist" {
		t.Fatalf("ID() = %q, want %q", p.ID(), "todoist")
	}
	if p.Name() != "Todoist" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "Todoist")
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
	u, err := DefaultProfile(goauth.Profile{"id": "td1", "full_name": "To Doist", "email": "t@odoist.com", "avatar_big": "https://td/a"}, goauth.TokenSet{})
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		t.Fatal("nil user")
	}
	if u.ID != "td1" {
		t.Fatalf("ID = %q, want %q", u.ID, "td1")
	}
	if u.Email != "t@odoist.com" {
		t.Fatalf("Email = %q, want %q", u.Email, "t@odoist.com")
	}
	if u.Name != "To Doist" {
		t.Fatalf("Name = %q, want %q", u.Name, "To Doist")
	}
	if u.Provider != "todoist" {
		t.Fatalf("Provider = %q, want %q", u.Provider, "todoist")
	}
}

func TestFetchUserInfo_SyncAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user": map[string]any{
				"id": "td1", "full_name": "To Doist", "email": "t@odoist.com", "avatar_big": "https://td/a",
			},
		})
	}))
	t.Cleanup(srv.Close)
	prev := syncAPIURL
	syncAPIURL = srv.URL
	t.Cleanup(func() { syncAPIURL = prev })

	p := New(Options{ClientID: "id", ClientSecret: "secret"}).(*goauth.OAuthProvider)
	profile, err := p.FetchUserInfo(context.Background(), goauth.TokenSet{AccessToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := DefaultProfile(profile, goauth.TokenSet{})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "td1" || u.Email != "t@odoist.com" {
		t.Fatalf("got %#v", u)
	}
}
