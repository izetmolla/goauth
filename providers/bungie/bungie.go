// Package bungie provides a Bungie sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/bungie"
//
//	bungie.New(bungie.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package bungie

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "bungie"

// Options configures the Bungie provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Bungie provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = nil
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	authParams := o.AuthorizationParams
	if authParams == nil {
		authParams = url.Values{"reauth": {"true"}}
	} else {
		if _, ok := authParams["reauth"]; !ok {
			authParams.Set("reauth", "true")
		}
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Bungie",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://www.bungie.net/en/OAuth/Authorize",
		TokenURL:            "https://www.bungie.net/platform/app/oauth/token/",
		AuthorizationParams: authParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error) {
	if len(p) == 0 && tokens.IDToken != "" {
		if claims, err := common.DecodeIDTokenPayload(tokens.IDToken); err == nil {
			p = claims
		}
	}
	f := common.MapUser(p)
	if f.ID == "" {
		f.ID = common.FirstNonEmpty(common.RawString(tokens.Raw, "membership_id"), common.RawString(tokens.Raw, "user_id"))
	}
	return &goauth.OAuthUser{ID: f.ID, Name: f.Name, Email: f.Email, Image: f.Image, Provider: ID}, nil
}
