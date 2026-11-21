// Package pinterest provides a Pinterest sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/pinterest"
//
//	pinterest.New(pinterest.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package pinterest

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "pinterest"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"user_accounts:read"}

// Options configures the Pinterest provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Pinterest provider.
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
		DisplayName:         "Pinterest",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://www.pinterest.com/oauth",
		TokenURL:            "https://api.pinterest.com/v5/oauth/token",
		UserInfoURL:         "https://api.pinterest.com/v5/user_account",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		AuthorizationStyle:  "header",
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	f := common.MapUser(p)
	return &goauth.OAuthUser{ID: f.ID, Name: f.Name, Email: f.Email, Image: f.Image, Provider: ID}, nil
}
