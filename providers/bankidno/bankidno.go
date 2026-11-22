// Package bankidno provides a BankID Norge sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/bankidno"
//
//	bankidno.New(bankidno.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package bankidno

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/bankid-no.
const ID = "bankid-no"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"openid", "profile"}

// Options configures the BankID Norge provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured BankID Norge provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = DefaultScopes
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "BankID Norge",
		Kind:                goauth.ProviderOIDC,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		Issuer:              "https://auth.bankid.no/auth/realms/prod",
		AuthorizationParams: o.AuthorizationParams,
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
