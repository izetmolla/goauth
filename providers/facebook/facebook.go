// Package facebook provides a Facebook sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/facebook"
//
//	facebook.New(facebook.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package facebook

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "facebook"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"email"}

// Options configures the Facebook provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Facebook provider.
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
		DisplayName:         "Facebook",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://www.facebook.com/v19.0/dialog/oauth",
		TokenURL:            "https://graph.facebook.com/oauth/access_token",
		UserInfoURL:         "https://graph.facebook.com/me?fields=id,name,email,picture",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	return &goauth.OAuthUser{
		ID:       common.String(p["id"]),
		Name:     common.String(p["name"]),
		Email:    common.String(p["email"]),
		Image:    common.NestedString(p, "picture.data.url"),
		Provider: ID,
	}, nil
}
