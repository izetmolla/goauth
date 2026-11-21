// Package trakt provides a Trakt sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/trakt"
//
//	trakt.New(trakt.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package trakt

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "trakt"

// Options configures the Trakt provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Trakt provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = nil
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Trakt",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://trakt.tv/oauth/authorize",
		TokenURL:            "https://api.trakt.tv/oauth/token",
		UserInfoURL:         "https://api.trakt.tv/users/me?extended=full",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	ids := common.Map(p["ids"])
	id := common.String(p["username"])
	if ids != nil {
		id = common.FirstNonEmpty(common.String(ids["slug"]), id)
	}
	return &goauth.OAuthUser{
		ID:       id,
		Name:     common.String(p["name"]),
		NickName: common.String(p["username"]),
		Image:    common.NestedString(p, "images.avatar.full"),
		Provider: ID,
	}, nil
}
