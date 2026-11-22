// Package spotify provides a Spotify sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/spotify"
//
//	spotify.New(spotify.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package spotify

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/spotify.
const ID = "spotify"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"user-read-email"}

// Options configures the Spotify provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Spotify provider.
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
		DisplayName:         "Spotify",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://accounts.spotify.com/authorize",
		TokenURL:            "https://accounts.spotify.com/api/token",
		UserInfoURL:         "https://api.spotify.com/v1/me",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	image := ""
	if imgs, ok := p["images"].([]any); ok && len(imgs) > 0 {
		if m := common.Map(imgs[0]); m != nil {
			image = common.String(m["url"])
		}
	}
	return &goauth.OAuthUser{
		ID:       common.String(p["id"]),
		Name:     common.String(p["display_name"]),
		Email:    common.String(p["email"]),
		Image:    image,
		Provider: ID,
	}, nil
}
