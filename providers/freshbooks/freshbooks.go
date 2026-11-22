// Package freshbooks provides a Freshbooks sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/freshbooks"
//
//	freshbooks.New(freshbooks.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package freshbooks

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/freshbooks.
const ID = "freshbooks"

// Options configures the Freshbooks provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Freshbooks provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = nil
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Freshbooks",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://auth.freshbooks.com/oauth/authorize",
		TokenURL:            "https://api.freshbooks.com/auth/oauth/token",
		UserInfoURL:         "https://api.freshbooks.com/auth/api/v1/users/me",
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
