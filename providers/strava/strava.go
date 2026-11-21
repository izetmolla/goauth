// Package strava provides a Strava sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/strava"
//
//	strava.New(strava.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package strava

import (
	"net/url"
	"strings"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "strava"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"read"}

// Options configures the Strava provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Strava provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = DefaultScopes
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	authParams := o.AuthorizationParams
	if authParams == nil {
		authParams = url.Values{"approval_prompt": {"auto"}}
	} else {
		if _, ok := authParams["approval_prompt"]; !ok {
			authParams.Set("approval_prompt", "auto")
		}
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Strava",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://www.strava.com/api/v3/oauth/authorize",
		TokenURL:            "https://www.strava.com/api/v3/oauth/token",
		UserInfoURL:         "https://www.strava.com/api/v3/athlete",
		AuthorizationParams: authParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		AuthorizationStyle:  "body",
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	return &goauth.OAuthUser{
		ID:        common.String(p["id"]),
		Name:      strings.TrimSpace(common.String(p["firstname"]) + " " + common.String(p["lastname"])),
		FirstName: common.String(p["firstname"]),
		LastName:  common.String(p["lastname"]),
		Image:     common.String(p["profile"]),
		Provider:  ID,
	}, nil
}
