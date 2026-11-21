// Package fusionauth provides a FusionAuth sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/fusionauth"
//
//	fusionauth.New(fusionauth.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//		Issuer:      "https://your-issuer.example",
//	})
package fusionauth

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "fusionauth"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"openid", "email", "profile", "offline_access"}

// Options configures the FusionAuth provider.
type Options struct {
	ClientID     string
	ClientSecret string
	// Issuer is the OIDC issuer URL (required unless a default is set).
	Issuer              string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured FusionAuth provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = DefaultScopes
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	issuer := o.Issuer
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "FusionAuth",
		Kind:                goauth.ProviderOIDC,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		Issuer:              issuer,
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckPKCE, goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	f := common.MapUser(p)
	return &goauth.OAuthUser{ID: f.ID, Name: f.Name, Email: f.Email, Image: f.Image, Provider: ID}, nil
}
