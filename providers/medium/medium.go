// Package medium provides a Medium sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/medium"
//
//	medium.New(medium.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package medium

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "medium"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"basicProfile"}

// Options configures the Medium provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Medium provider.
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
		DisplayName:         "Medium",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://medium.com/m/oauth/authorize",
		TokenURL:            "https://api.medium.com/v1/tokens",
		UserInfoURL:         "https://api.medium.com/v1/me",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	data := common.Map(p["data"])
	if data == nil {
		data = p
	}
	return &goauth.OAuthUser{
		ID:       common.String(data["id"]),
		Name:     common.String(data["name"]),
		Image:    common.String(data["imageUrl"]),
		Provider: ID,
	}, nil
}
