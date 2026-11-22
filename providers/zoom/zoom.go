// Package zoom provides a Zoom sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/zoom"
//
//	zoom.New(zoom.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package zoom

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/zoom.
const ID = "zoom"

// Options configures the Zoom provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Zoom provider.
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
		DisplayName:         "Zoom",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://zoom.us/oauth/authorize",
		TokenURL:            "https://zoom.us/oauth/token",
		UserInfoURL:         "https://api.zoom.us/v2/users/me",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		AuthorizationStyle:  "header",
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	return &goauth.OAuthUser{
		ID:        common.String(p["id"]),
		Name:      common.String(p["display_name"]),
		Email:     common.String(p["email"]),
		Image:     common.String(p["pic_url"]),
		FirstName: common.String(p["first_name"]),
		LastName:  common.String(p["last_name"]),
		Provider:  ID,
	}, nil
}
