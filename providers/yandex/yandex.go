// Package yandex provides a Yandex sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/yandex"
//
//	yandex.New(yandex.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package yandex

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/yandex.
const ID = "yandex"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"login:info", "login:email", "login:avatar"}

// Options configures the Yandex provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Yandex provider.
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
		DisplayName:         "Yandex",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://oauth.yandex.ru/authorize",
		TokenURL:            "https://oauth.yandex.ru/token",
		UserInfoURL:         "https://login.yandex.ru/info?format=json",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	image := ""
	if common.String(p["default_avatar_id"]) != "" {
		image = "https://avatars.yandex.net/get-yapic/" + common.String(p["default_avatar_id"]) + "/islands-200"
	}
	return &goauth.OAuthUser{
		ID:       common.String(p["id"]),
		Name:     common.FirstNonEmpty(common.String(p["real_name"]), common.String(p["display_name"]), common.String(p["login"])),
		Email:    common.FirstNonEmpty(common.String(p["default_email"]), common.String(p["emails"])),
		Image:    image,
		Provider: ID,
	}, nil
}
