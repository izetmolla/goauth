// Package discord provides a Discord sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/discord"
//
//	discord.New(discord.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package discord

import (
	"net/url"
	"strings"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "discord"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"identify", "email"}

// Options configures the Discord provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Discord provider.
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
		DisplayName:         "Discord",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://discord.com/api/oauth2/authorize",
		TokenURL:            "https://discord.com/api/oauth2/token",
		UserInfoURL:         "https://discord.com/api/users/@me",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	image := common.String(p["image_url"])
	if image == "" {
		avatar := common.String(p["avatar"])
		id := common.String(p["id"])
		if avatar == "" {
			image = "https://cdn.discordapp.com/embed/avatars/0.png"
		} else {
			format := "png"
			if strings.HasPrefix(avatar, "a_") {
				format = "gif"
			}
			image = "https://cdn.discordapp.com/avatars/" + id + "/" + avatar + "." + format
		}
	}
	return &goauth.OAuthUser{
		ID:       common.String(p["id"]),
		Name:     common.FirstNonEmpty(common.String(p["global_name"]), common.String(p["username"])),
		Email:    common.String(p["email"]),
		Image:    image,
		Provider: ID,
	}, nil
}
