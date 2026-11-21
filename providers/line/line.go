// Package line provides a LINE sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/line"
//
//	line.New(line.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package line

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "line"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"profile", "openid", "email"}

// Options configures the LINE provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured LINE provider.
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
		DisplayName:         "LINE",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://access.line.me/oauth2/v2.1/authorize",
		TokenURL:            "https://api.line.me/oauth2/v2.1/token",
		UserInfoURL:         "https://api.line.me/v2/profile",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		AuthorizationStyle:  "body",
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error) {
	email := ""
	if tokens.IDToken != "" {
		if claims, err := common.DecodeIDTokenPayload(tokens.IDToken); err == nil {
			email = common.String(claims["email"])
		}
	}
	return &goauth.OAuthUser{
		ID:       common.String(p["userId"]),
		Name:     common.String(p["displayName"]),
		Email:    email,
		Image:    common.String(p["pictureUrl"]),
		Provider: ID,
	}, nil
}
