// Package wordpress provides a WordPress.com sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/wordpress"
//
//	wordpress.New(wordpress.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package wordpress

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/wordpress.
const ID = "wordpress"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"auth"}

// Options configures the WordPress.com provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured WordPress.com provider.
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
		DisplayName:         "WordPress.com",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://public-api.wordpress.com/oauth2/authorize",
		TokenURL:            "https://public-api.wordpress.com/oauth2/token",
		UserInfoURL:         "https://public-api.wordpress.com/rest/v1/me",
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
