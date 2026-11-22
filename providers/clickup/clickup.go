// Package clickup provides a ClickUp sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/clickup"
//
//	clickup.New(clickup.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package clickup

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/click-up.
const ID = "click-up"

// Options configures the ClickUp provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured ClickUp provider.
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
		DisplayName:         "ClickUp",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://app.clickup.com/api",
		TokenURL:            "https://api.clickup.com/api/v2/oauth/token",
		UserInfoURL:         "https://api.clickup.com/api/v2/user",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	user := common.Map(p["user"])
	if user == nil {
		user = p
	}
	return &goauth.OAuthUser{
		ID:       common.String(user["id"]),
		Name:     common.String(user["username"]),
		Email:    common.String(user["email"]),
		Image:    common.String(user["profilePicture"]),
		Provider: ID,
	}, nil
}
