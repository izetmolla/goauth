// Package bitbucket provides a Bitbucket sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/bitbucket"
//
//	bitbucket.New(bitbucket.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package bitbucket

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "bitbucket"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"account"}

// Options configures the Bitbucket provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Bitbucket provider.
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
		DisplayName:         "Bitbucket",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://bitbucket.org/site/oauth2/authorize",
		TokenURL:            "https://bitbucket.org/site/oauth2/access_token",
		UserInfoURL:         "https://api.bitbucket.org/2.0/user",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	return &goauth.OAuthUser{
		ID:       common.String(p["uuid"]),
		Name:     common.FirstNonEmpty(common.String(p["display_name"]), common.String(p["username"])),
		NickName: common.String(p["username"]),
		Image:    common.NestedString(p, "links.avatar.href"),
		Provider: ID,
	}, nil
}
