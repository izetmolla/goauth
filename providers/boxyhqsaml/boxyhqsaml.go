// Package boxyhqsaml provides a BoxyHQ SAML sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/boxyhqsaml"
//
//	boxyhqsaml.New(boxyhqsaml.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//		Issuer:      "https://your-issuer.example",
//	})
package boxyhqsaml

import (
	"net/url"
	"strings"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/boxyhq-saml.
const ID = "boxyhq-saml"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"openid"}

// Options configures the BoxyHQ SAML provider.
type Options struct {
	ClientID     string
	ClientSecret string
	// Issuer is the base URL of the identity server (no trailing path required).
	Issuer              string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured BoxyHQ SAML provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = DefaultScopes
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	issuer := strings.TrimRight(o.Issuer, "/")
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "BoxyHQ SAML",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    issuer + "/api/oauth/authorize",
		TokenURL:            issuer + "/api/oauth/token",
		UserInfoURL:         issuer + "/api/oauth/userinfo",
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
