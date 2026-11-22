// Package azuredevops provides a Azure DevOps sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/azuredevops"
//
//	azuredevops.New(azuredevops.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package azuredevops

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/azure-devops.
const ID = "azure-devops"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"vso.profile"}

// Options configures the Azure DevOps provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Azure DevOps provider.
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
		authParams = url.Values{"response_type": {"Assertion"}}
	} else {
		if _, ok := authParams["response_type"]; !ok {
			authParams.Set("response_type", "Assertion")
		}
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Azure DevOps",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://app.vssps.visualstudio.com/oauth2/authorize",
		TokenURL:            "https://app.vssps.visualstudio.com/oauth2/token",
		UserInfoURL:         "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=6.0",
		AuthorizationParams: authParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	f := common.MapUser(p)
	return &goauth.OAuthUser{ID: f.ID, Name: f.Name, Email: f.Email, Image: f.Image, Provider: ID}, nil
}
