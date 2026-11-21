// Package twitter provides a Twitter sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/twitter"
//
//	twitter.New(twitter.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package twitter

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "twitter"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"users.read", "tweet.read", "offline.access"}

// Options configures the Twitter provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Twitter provider.
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
		DisplayName:         "Twitter",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://x.com/i/oauth2/authorize",
		TokenURL:            "https://api.x.com/2/oauth2/token",
		UserInfoURL:         "https://api.x.com/2/users/me?user.fields=profile_image_url",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckPKCE, goauth.CheckState},
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
		NickName: common.String(data["username"]),
		Image:    common.String(data["profile_image_url"]),
		Provider: ID,
	}, nil
}
