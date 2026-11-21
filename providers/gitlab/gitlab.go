// Package gitlab provides a GitLab sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/gitlab"
//
//	gitlab.New(gitlab.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//		// BaseURL: "https://gitlab.com",
//	})
package gitlab

import (
	"net/url"
	"strings"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "gitlab"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"read_user"}

// Options configures the GitLab provider.
type Options struct {
	ClientID     string
	ClientSecret string
	// BaseURL defaults to "https://gitlab.com".
	BaseURL             string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured GitLab provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = DefaultScopes
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	base := o.BaseURL
	if base == "" {
		base = "https://gitlab.com"
	}
	base = strings.TrimRight(base, "/")
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "GitLab",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    base + "/oauth/authorize",
		TokenURL:            base + "/oauth/token",
		UserInfoURL:         base + "/api/v4/user",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	return &goauth.OAuthUser{
		ID:       common.FirstNonEmpty(common.String(p["sub"]), common.String(p["id"])),
		Name:     common.FirstNonEmpty(common.String(p["name"]), common.String(p["username"])),
		Email:    common.String(p["email"]),
		Image:    common.String(p["avatar_url"]),
		Provider: ID,
	}, nil
}
