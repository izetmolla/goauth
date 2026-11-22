package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
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
	if p.ID() != "github" {
		t.Fatalf("ID() = %q, want %q", p.ID(), "github")
	}
	if p.Name() != "GitHub" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "GitHub")
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
	u, err := DefaultProfile(goauth.Profile{
		"id": float64(42), "login": "octocat", "name": "The Octocat",
		"email": "octocat@github.com", "avatar_url": "https://gh/a",
	}, goauth.TokenSet{})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "42" || u.Email != "octocat@github.com" || u.Name != "The Octocat" || u.Provider != "github" {
		t.Fatalf("got %#v", u)
	}
}

func TestFetchUserInfo_WithEmailsFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 42, "login": "octocat", "name": "The Octocat", "avatar_url": "https://gh/a",
		})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"email": "secondary@gh.com", "primary": false, "verified": true},
			{"email": "primary@gh.com", "primary": true, "verified": true},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	prevUser, prevEmails := userAPIURL, emailsAPIURL
	userAPIURL = srv.URL + "/user"
	emailsAPIURL = srv.URL + "/user/emails"
	t.Cleanup(func() { userAPIURL, emailsAPIURL = prevUser, prevEmails })

	p := New(Options{ClientID: "id", ClientSecret: "secret"}).(*goauth.OAuthProvider)
	profile, err := p.FetchUserInfo(context.Background(), goauth.TokenSet{AccessToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if common.String(profile["email"]) != "primary@gh.com" {
		t.Fatalf("email = %v", profile["email"])
	}
	u, err := DefaultProfile(profile, goauth.TokenSet{})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "42" || u.Email != "primary@gh.com" || u.NickName != "octocat" {
		t.Fatalf("got %#v", u)
	}
}

// An unverified address may belong to someone else, so it must never become
// the profile email.
func TestVerifiedEmailIgnoresUnverified(t *testing.T) {
	cases := []struct {
		name   string
		emails []githubEmail
		want   string
	}{
		{"primary verified", []githubEmail{{"a@x", false, true}, {"p@x", true, true}}, "p@x"},
		{"primary unverified falls back to verified", []githubEmail{{"p@x", true, false}, {"v@x", false, true}}, "v@x"},
		{"none verified", []githubEmail{{"p@x", true, false}, {"o@x", false, false}}, ""},
	}
	for _, tc := range cases {
		got, ok := verifiedEmail(tc.emails)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: got %q %v, want %q", tc.name, got, ok, tc.want)
		}
	}
}
