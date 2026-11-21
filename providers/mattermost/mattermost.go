// Package mattermost provides a Mattermost sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/mattermost"
//
//	mattermost.New(mattermost.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//		Issuer:      "https://your-issuer.example",
//	})
package mattermost

import (
	"net/url"
	"strings"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "mattermost"

// Options configures the Mattermost provider.
type Options struct {
	ClientID     string
	ClientSecret string
	// Issuer is the base URL of the identity server (no trailing path required).
	Issuer              string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Mattermost provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = nil
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	issuer := strings.TrimRight(o.Issuer, "/")
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Mattermost",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    issuer + "/oauth/authorize",
		TokenURL:            issuer + "/oauth/access_token",
		UserInfoURL:         issuer + "/api/v4/users/me",
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
