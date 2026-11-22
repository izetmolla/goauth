// Package coinbase provides a Coinbase sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/coinbase"
//
//	coinbase.New(coinbase.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package coinbase

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/coinbase.
const ID = "coinbase"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"wallet:user:email", "wallet:user:read"}

// Options configures the Coinbase provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Coinbase provider.
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
		DisplayName:         "Coinbase",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://login.coinbase.com/oauth2/auth",
		TokenURL:            "https://login.coinbase.com/oauth2/token",
		UserInfoURL:         "https://api.coinbase.com/v2/user",
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
	return &goauth.OAuthUser{
		ID:       common.String(data["id"]),
		Name:     common.String(data["name"]),
		Email:    common.String(data["email"]),
		Image:    common.String(data["avatar_url"]),
		Provider: ID,
	}, nil
}
