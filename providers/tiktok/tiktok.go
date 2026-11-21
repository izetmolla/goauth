// Package tiktok provides a TikTok sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/tiktok"
//
//	tiktok.New(tiktok.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package tiktok

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "tiktok"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"user.info.basic"}

// Options configures the TikTok provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured TikTok provider.
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
		authParams = url.Values{}
	}
	authParams.Set("client_key", o.ClientID)
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "TikTok",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://www.tiktok.com/v2/auth/authorize",
		TokenURL:            "https://open.tiktokapis.com/v2/oauth/token/",
		UserInfoURL:         "https://open.tiktokapis.com/v2/user/info/?fields=open_id,avatar_url,display_name",
		AuthorizationParams: authParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		AuthorizationStyle:  "body",
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	data := common.Map(p["data"])
	user := p
	if data != nil {
		if u := common.Map(data["user"]); u != nil {
			user = u
		}
	}
	return &goauth.OAuthUser{
		ID:       common.String(user["open_id"]),
		Name:     common.String(user["display_name"]),
		Image:    common.String(user["avatar_url"]),
		Provider: ID,
	}, nil
}
