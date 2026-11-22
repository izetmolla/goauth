// Package hubspot provides a HubSpot sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/hubspot"
//
//	hubspot.New(hubspot.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package hubspot

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/hubspot.
const ID = "hubspot"

// Options configures the HubSpot provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured HubSpot provider.
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
		DisplayName:         "HubSpot",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://app.hubspot.com/oauth/authorize",
		TokenURL:            "https://api.hubapi.com/oauth/v1/token",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error) {
	// HubSpot token response includes user / hub_id; refresh userinfo via token raw.
	id := common.FirstNonEmpty(common.String(p["user_id"]), common.RawString(tokens.Raw, "user_id"), common.String(p["user"]))
	return &goauth.OAuthUser{
		ID:       id,
		Email:    common.FirstNonEmpty(common.String(p["user"]), common.RawString(tokens.Raw, "user")),
		Provider: ID,
	}, nil
}
