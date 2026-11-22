// Package azureadb2c provides a Azure AD B2C sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/azureadb2c"
//
//	azureadb2c.New(azureadb2c.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//		Issuer:      "https://your-issuer.example",
//	})
package azureadb2c

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/azure-ad-b2c.
const ID = "azure-ad-b2c"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"openid", "profile", "email"}

// Options configures the Azure AD B2C provider.
type Options struct {
	ClientID     string
	ClientSecret string
	// Issuer is the OIDC issuer URL (required unless a default is set).
	Issuer              string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Azure AD B2C provider.
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
		DisplayName:         "Azure AD B2C",
		Kind:                goauth.ProviderOIDC,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		Issuer:              issuer,
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
