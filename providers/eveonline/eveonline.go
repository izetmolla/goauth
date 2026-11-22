// Package eveonline provides a EVE Online sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/eveonline"
//
//	eveonline.New(eveonline.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package eveonline

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/eveonline.
const ID = "eveonline"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"publicData"}

// Options configures the EVE Online provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured EVE Online provider.
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
		DisplayName:         "EVE Online",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://login.eveonline.com/v2/oauth/authorize",
		TokenURL:            "https://login.eveonline.com/v2/oauth/token",
		UserInfoURL:         "https://login.eveonline.com/oauth/verify",
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
