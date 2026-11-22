// Package dropbox provides a Dropbox sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/dropbox"
//
//	dropbox.New(dropbox.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package dropbox

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/dropbox.
const ID = "dropbox"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"account_info.read"}

// Options configures the Dropbox provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Dropbox provider.
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
		authParams = url.Values{"token_access_type": {"offline"}}
	} else {
		if _, ok := authParams["token_access_type"]; !ok {
			authParams.Set("token_access_type", "offline")
		}
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Dropbox",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://www.dropbox.com/oauth2/authorize",
		TokenURL:            "https://api.dropboxapi.com/oauth2/token",
		UserInfoURL:         "https://api.dropboxapi.com/2/users/get_current_account",
		UserInfoMethod:      "POST",
		AuthorizationParams: authParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	name := common.Map(p["name"])
	display := ""
	if name != nil {
		display = common.String(name["display_name"])
	}
	return &goauth.OAuthUser{
		ID:       common.String(p["account_id"]),
		Name:     display,
		Email:    common.String(p["email"]),
		Image:    common.String(p["profile_photo_url"]),
		Provider: ID,
	}, nil
}
