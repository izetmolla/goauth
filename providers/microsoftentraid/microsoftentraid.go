// Package microsoftentraid provides a Microsoft Entra ID sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/microsoftentraid"
//
//	microsoftentraid.New(microsoftentraid.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//		Issuer:      "https://your-issuer.example",
//	})
package microsoftentraid

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/microsoft-entra-id.
const ID = "microsoft-entra-id"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"openid", "profile", "email", "User.Read"}

// Options configures the Microsoft Entra ID provider.
type Options struct {
	ClientID     string
	ClientSecret string
	// Issuer defaults to "https://login.microsoftonline.com/common/v2.0" when empty.
	Issuer              string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Microsoft Entra ID provider.
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
	if issuer == "" {
		issuer = "https://login.microsoftonline.com/common/v2.0"
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Microsoft Entra ID",
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
