// Package threads provides a Threads sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/threads"
//
//	threads.New(threads.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package threads

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "threads"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"threads_basic"}

// Options configures the Threads provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Threads provider.
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
		DisplayName:         "Threads",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://threads.net/oauth/authorize",
		TokenURL:            "https://graph.threads.net/oauth/access_token",
		UserInfoURL:         "https://graph.threads.net/v1.0/me?fields=id,username,threads_profile_picture_url",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		AuthorizationStyle:  "body",
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	return &goauth.OAuthUser{
		ID:       common.String(p["id"]),
		Name:     common.String(p["username"]),
		NickName: common.String(p["username"]),
		Image:    common.String(p["threads_profile_picture_url"]),
		Provider: ID,
	}, nil
}
