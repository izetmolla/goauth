// Package mastodon provides a Mastodon sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/mastodon"
//
//	mastodon.New(mastodon.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//		Issuer:      "https://your-issuer.example",
//	})
package mastodon

import (
	"net/url"
	"strings"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/mastodon.
const ID = "mastodon"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"read:accounts"}

// Options configures the Mastodon provider.
type Options struct {
	ClientID     string
	ClientSecret string
	// Issuer is the base URL of the identity server (no trailing path required).
	Issuer              string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Mastodon provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = DefaultScopes
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	issuer := strings.TrimRight(o.Issuer, "/")
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Mastodon",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    issuer + "/oauth/authorize",
		TokenURL:            issuer + "/oauth/token",
		UserInfoURL:         issuer + "/api/v1/accounts/verify_credentials",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	return &goauth.OAuthUser{
		ID:       common.String(p["id"]),
		Name:     common.FirstNonEmpty(common.String(p["display_name"]), common.String(p["username"])),
		NickName: common.String(p["username"]),
		Image:    common.String(p["avatar"]),
		Provider: ID,
	}, nil
}
