// Package naver provides a Naver sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/naver"
//
//	naver.New(naver.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package naver

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "naver"

// Options configures the Naver provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Naver provider.
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
		DisplayName:         "Naver",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://nid.naver.com/oauth2.0/authorize",
		TokenURL:            "https://nid.naver.com/oauth2.0/token",
		UserInfoURL:         "https://openapi.naver.com/v1/nid/me",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	resp := common.Map(p["response"])
	if resp == nil {
		resp = p
	}
	return &goauth.OAuthUser{
		ID:       common.String(resp["id"]),
		Name:     common.String(resp["nickname"]),
		Email:    common.String(resp["email"]),
		Image:    common.String(resp["profile_image"]),
		Provider: ID,
	}, nil
}
