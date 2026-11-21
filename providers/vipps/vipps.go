// Package vipps provides a Vipps MobilePay sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/vipps"
//
//	vipps.New(vipps.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package vipps

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "vipps"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"openid", "name", "email"}

// Options configures the Vipps MobilePay provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Vipps MobilePay provider.
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
		DisplayName:         "Vipps MobilePay",
		Kind:                goauth.ProviderOIDC,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		Issuer:              "https://api.vipps.no/access-management-1.0/access/",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckPKCE, goauth.CheckState, goauth.CheckNonce},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	f := common.MapUser(p)
	return &goauth.OAuthUser{ID: f.ID, Name: f.Name, Email: f.Email, Image: f.Image, Provider: ID}, nil
}
