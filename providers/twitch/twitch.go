// Package twitch provides a Twitch sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/twitch"
//
//	twitch.New(twitch.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package twitch

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/twitch.
const ID = "twitch"

const defaultClaims = `{"id_token":{"email":null,"picture":null,"preferred_username":null}}`

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"openid", "user:read:email"}

// Options configures the Twitch provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Twitch provider.
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
		authParams = url.Values{"claims": {defaultClaims}}
	} else if _, ok := authParams["claims"]; !ok {
		authParams.Set("claims", defaultClaims)
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Twitch",
		Kind:                goauth.ProviderOIDC,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		Issuer:              "https://id.twitch.tv/oauth2",
		AuthorizationParams: authParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckPKCE, goauth.CheckState, goauth.CheckNonce},
		AuthorizationStyle:  "body",
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	f := common.MapUser(p)
	return &goauth.OAuthUser{ID: f.ID, Name: f.Name, Email: f.Email, Image: f.Image, Provider: ID}, nil
}
