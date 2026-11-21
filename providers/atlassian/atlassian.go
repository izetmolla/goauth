// Package atlassian provides a Atlassian sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/atlassian"
//
//	atlassian.New(atlassian.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package atlassian

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "atlassian"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"read:me"}

// Options configures the Atlassian provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Atlassian provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = DefaultScopes
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	authParams := o.AuthorizationParams
	if authParams == nil {
		authParams = url.Values{"audience": {"api.atlassian.com"}}
	} else {
		if _, ok := authParams["audience"]; !ok {
			authParams.Set("audience", "api.atlassian.com")
		}
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Atlassian",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://auth.atlassian.com/authorize",
		TokenURL:            "https://auth.atlassian.com/oauth/token",
		UserInfoURL:         "https://api.atlassian.com/me",
		AuthorizationParams: authParams,
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
