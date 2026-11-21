// Package zoho provides a Zoho sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/zoho"
//
//	zoho.New(zoho.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package zoho

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "zoho"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"AaaServer.profile.Read"}

// Options configures the Zoho provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Zoho provider.
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
		DisplayName:         "Zoho",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://accounts.zoho.com/oauth/v2/auth",
		TokenURL:            "https://accounts.zoho.com/oauth/v2/token",
		UserInfoURL:         "https://accounts.zoho.com/oauth/user/info",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	f := common.MapUser(p)
	return &goauth.OAuthUser{ID: f.ID, Name: f.Name, Email: f.Email, Image: f.Image, Provider: ID}, nil
}
