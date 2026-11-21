// Package patreon provides a Patreon sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/patreon"
//
//	patreon.New(patreon.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package patreon

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "patreon"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"identity", "identity[email]"}

// Options configures the Patreon provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Patreon provider.
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
		DisplayName:         "Patreon",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://www.patreon.com/oauth2/authorize",
		TokenURL:            "https://www.patreon.com/api/oauth2/token",
		UserInfoURL:         "https://www.patreon.com/api/oauth2/v2/identity?fields%5Buser%5D=email,first_name,image_url,last_name,full_name",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	data := common.Map(p["data"])
	if data == nil {
		data = p
	}
	attrs := common.Map(data["attributes"])
	if attrs == nil {
		attrs = map[string]any{}
	}
	return &goauth.OAuthUser{
		ID:        common.String(data["id"]),
		Name:      common.String(attrs["full_name"]),
		Email:     common.String(attrs["email"]),
		Image:     common.String(attrs["image_url"]),
		FirstName: common.String(attrs["first_name"]),
		LastName:  common.String(attrs["last_name"]),
		Provider:  ID,
	}, nil
}
