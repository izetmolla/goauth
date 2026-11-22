// Package foursquare provides a Foursquare sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/foursquare"
//
//	foursquare.New(foursquare.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package foursquare

import (
	"net/url"
	"strings"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/foursquare.
const ID = "foursquare"

// Options configures the Foursquare provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Foursquare provider.
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
		DisplayName:         "Foursquare",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://foursquare.com/oauth2/authenticate",
		TokenURL:            "https://foursquare.com/oauth2/access_token",
		UserInfoURL:         "https://api.foursquare.com/v2/users/self",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	resp := common.Map(p["response"])
	user := p
	if resp != nil {
		if u := common.Map(resp["user"]); u != nil {
			user = u
		}
	}
	photo := common.Map(user["photo"])
	image := ""
	if photo != nil {
		image = common.String(photo["prefix"]) + "original" + common.String(photo["suffix"])
	}
	return &goauth.OAuthUser{
		ID:       common.String(user["id"]),
		Name:     strings.TrimSpace(common.String(user["firstName"]) + " " + common.String(user["lastName"])),
		Email:    common.NestedString(user, "contact.email"),
		Image:    image,
		Provider: ID,
	}, nil
}
