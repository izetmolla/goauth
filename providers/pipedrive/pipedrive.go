// Package pipedrive provides a Pipedrive sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/pipedrive"
//
//	pipedrive.New(pipedrive.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package pipedrive

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/pipedrive.
const ID = "pipedrive"

// Options configures the Pipedrive provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Pipedrive provider.
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
		DisplayName:         "Pipedrive",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://oauth.pipedrive.com/oauth/authorize",
		TokenURL:            "https://oauth.pipedrive.com/oauth/token",
		UserInfoURL:         "https://api.pipedrive.com/v1/users/me",
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
		Image:    common.String(data["icon_url"]),
		Provider: ID,
	}, nil
}
