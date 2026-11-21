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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "github"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"read:user", "user:email"}

// Overridable in tests.
var (
	userAPIURL   = "https://api.github.com/user"
	emailsAPIURL = "https://api.github.com/user/emails"
	httpClient   = http.DefaultClient
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

func fetchUserInfo(ctx context.Context, tokens goauth.TokenSet) (goauth.Profile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userAPIURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "goauth")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("github userinfo: status %d: %s", resp.StatusCode, b)
	}
	var profile goauth.Profile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, err
	}
	if common.String(profile["email"]) == "" {
		er, err := http.NewRequestWithContext(ctx, http.MethodGet, emailsAPIURL, nil)
		if err == nil {
			er.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			er.Header.Set("User-Agent", "goauth")
			er.Header.Set("Accept", "application/json")
			if eres, err := httpClient.Do(er); err == nil {
				defer eres.Body.Close()
				if eres.StatusCode >= 200 && eres.StatusCode < 300 {
					var emails []map[string]any
					if json.NewDecoder(eres.Body).Decode(&emails) == nil {
						for _, e := range emails {
							if e["primary"] == true {
								profile["email"] = e["email"]
								break
							}
						}
						if common.String(profile["email"]) == "" && len(emails) > 0 {
							profile["email"] = emails[0]["email"]
						}
					}
				}
			}
		}
	}
	return profile, nil
}
