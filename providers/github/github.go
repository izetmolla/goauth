// Package github provides a GitHub sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/github"
//
//	github.New(github.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package github

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/github.
const ID = "github"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"read:user", "user:email"}

// Overridable in tests.
var (
	userAPIURL   = "https://api.github.com/user"
	emailsAPIURL = "https://api.github.com/user/emails"
	httpClient   = common.HTTPClient
)

// Options configures the GitHub provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured GitHub provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = DefaultScopes
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "GitHub",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://github.com/login/oauth/authorize",
		TokenURL:            "https://github.com/login/oauth/access_token",
		UserInfoURL:         "https://api.github.com/user",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
		FetchUserInfo:       fetchUserInfo,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	return &goauth.OAuthUser{
		ID:       common.String(p["id"]),
		Name:     common.FirstNonEmpty(common.String(p["name"]), common.String(p["login"])),
		Email:    common.String(p["email"]),
		Image:    common.String(p["avatar_url"]),
		NickName: common.String(p["login"]),
		Provider: ID,
	}, nil
}

// fetchUserInfo loads the GitHub user. When the profile has no public email,
// it reads /user/emails and uses the primary address, or else the first one,
// but only if GitHub reports it as verified: an unverified address could
// belong to someone else.
func fetchUserInfo(ctx context.Context, tokens goauth.TokenSet) (goauth.Profile, error) {
	var profile goauth.Profile
	if err := getJSON(ctx, userAPIURL, tokens.AccessToken, "github userinfo", &profile); err != nil {
		return nil, err
	}
	if common.String(profile["email"]) != "" {
		return profile, nil
	}
	var emails []githubEmail
	// The emails scope is optional; without it the profile simply has no email.
	if err := getJSON(ctx, emailsAPIURL, tokens.AccessToken, "github emails", &emails); err != nil {
		return profile, nil //nolint:nilerr // a missing email is not a sign-in failure
	}
	if e, ok := verifiedEmail(emails); ok {
		profile["email"] = e
		profile["email_verified"] = true
	}
	return profile, nil
}

// githubEmail is one entry of GET /user/emails.
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// verifiedEmail returns the primary address if it is verified, otherwise the
// first verified one.
func verifiedEmail(emails []githubEmail) (string, bool) {
	for _, primaryOnly := range []bool{true, false} {
		for _, e := range emails {
			if e.Verified && e.Email != "" && (e.Primary || !primaryOnly) {
				return e.Email, true
			}
		}
	}
	return "", false
}

// getJSON performs an authenticated GitHub API GET and decodes the response.
func getJSON(ctx context.Context, url, accessToken, what string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "goauth")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	defer resp.Body.Close()
	return common.DecodeJSON(resp, what, v)
}
