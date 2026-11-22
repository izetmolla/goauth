// Package kakao provides a Kakao sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/kakao"
//
//	kakao.New(kakao.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package kakao

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/kakao.
const ID = "kakao"

// Options configures the Kakao provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Kakao provider.
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
		DisplayName:         "Kakao",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://kauth.kakao.com/oauth/authorize",
		TokenURL:            "https://kauth.kakao.com/oauth/token",
		UserInfoURL:         "https://kapi.kakao.com/v2/user/me",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	kakao := common.Map(p["kakao_account"])
	profile := map[string]any{}
	if kakao != nil {
		profile = common.Map(kakao["profile"])
		if profile == nil {
			profile = map[string]any{}
		}
	}
	return &goauth.OAuthUser{
		ID:       common.String(p["id"]),
		Name:     common.String(profile["nickname"]),
		Email:    common.String(kakao["email"]),
		Image:    common.FirstNonEmpty(common.String(profile["profile_image_url"]), common.String(profile["thumbnail_image_url"])),
		Provider: ID,
	}, nil
}
