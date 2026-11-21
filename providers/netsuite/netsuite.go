// Package netsuite provides a NetSuite sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/netsuite"
//
//	netsuite.New(netsuite.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//		AccountID:   "YOUR_ACCOUNT_ID",
//	})
package netsuite

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "netsuite"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"rest_webservices", "restlets"}

// Options configures the NetSuite provider.
type Options struct {
	ClientID     string
	ClientSecret string
	// AccountID is the NetSuite account id (e.g. TSTDRV123456).
	AccountID           string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured NetSuite provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = DefaultScopes
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	account := o.AccountID
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "NetSuite",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://" + account + ".app.netsuite.com/app/login/oauth2/authorize.nl",
		TokenURL:            "https://" + account + ".suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error) {
	f := common.MapUser(p)
	if f.ID == "" {
		f.ID = common.RawString(tokens.Raw, "entity")
	}
	return &goauth.OAuthUser{ID: f.ID, Name: f.Name, Email: f.Email, Image: f.Image, Provider: ID}, nil
}
