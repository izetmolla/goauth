// Package notion provides a Notion sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/notion"
//
//	notion.New(notion.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package notion

import (
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "notion"

// Options configures the Notion provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Notion provider.
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
		authParams = url.Values{"owner": {"user"}}
	} else {
		if _, ok := authParams["owner"]; !ok {
			authParams.Set("owner", "user")
		}
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Notion",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://api.notion.com/v1/oauth/authorize",
		TokenURL:            "https://api.notion.com/v1/oauth/token",
		AuthorizationParams: authParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		AuthorizationStyle:  "header",
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error) {
	var owner map[string]any
	if tokens.Raw != nil {
		owner = common.Map(tokens.Raw["owner"])
	}
	user := map[string]any{}
	if owner != nil {
		user = common.Map(owner["user"])
		if user == nil {
			user = map[string]any{}
		}
	}
	if len(p) > 0 {
		user = p
	}
	return &goauth.OAuthUser{
		ID:       common.String(user["id"]),
		Name:     common.String(user["name"]),
		Image:    common.String(user["avatar_url"]),
		Provider: ID,
	}, nil
}
