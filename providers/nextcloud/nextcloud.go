// Package nextcloud provides a Nextcloud sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/nextcloud"
//
//	nextcloud.New(nextcloud.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//		Issuer:      "https://your-issuer.example",
//	})
package nextcloud

import (
	"net/url"
	"strings"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "nextcloud"

// Options configures the Nextcloud provider.
type Options struct {
	ClientID     string
	ClientSecret string
	// Issuer is the base URL of the identity server (no trailing path required).
	Issuer              string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Nextcloud provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = nil
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	issuer := strings.TrimRight(o.Issuer, "/")
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Nextcloud",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    issuer + "/apps/oauth2/authorize",
		TokenURL:            issuer + "/apps/oauth2/api/v1/token",
		UserInfoURL:         issuer + "/ocs/v2.php/cloud/user?format=json",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	ocs := common.Map(p["ocs"])
	data := p
	if ocs != nil {
		if d := common.Map(ocs["data"]); d != nil {
			data = d
		}
	}
	return &goauth.OAuthUser{
		ID:       common.String(data["id"]),
		Name:     common.FirstNonEmpty(common.String(data["display-name"]), common.String(data["displayname"])),
		Email:    common.String(data["email"]),
		Provider: ID,
	}, nil
}
