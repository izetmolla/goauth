// Package apple provides an Apple sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/apple"
//
//	apple.New(apple.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package apple

import (
	"net/url"
	"strings"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/apple.
const ID = "apple"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"name", "email"}

// Options configures the Apple provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Apple provider.
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
		authParams = url.Values{"response_mode": {"form_post"}}
	} else {
		if _, ok := authParams["response_mode"]; !ok {
			authParams.Set("response_mode", "form_post")
		}
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Apple",
		Kind:                goauth.ProviderOIDC,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		Issuer:              "https://appleid.apple.com",
		AuthorizationURL:    "https://appleid.apple.com/auth/authorize",
		TokenURL:            "https://appleid.apple.com/auth/token",
		AuthorizationParams: authParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckPKCE, goauth.CheckState, goauth.CheckNonce},
		AuthorizationStyle:  "body",
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error) {
	if len(p) == 0 && tokens.IDToken != "" {
		claims, err := common.DecodeIDTokenPayload(tokens.IDToken)
		if err != nil {
			return nil, err
		}
		p = claims
	}
	name := common.String(p["email"])
	if user := common.Map(p["user"]); user != nil {
		if n := common.Map(user["name"]); n != nil {
			name = strings.TrimSpace(common.FirstNonEmpty(
				common.String(n["firstName"])+" "+common.String(n["lastName"]),
				name,
			))
		}
	}
	f := common.MapUser(p)
	return &goauth.OAuthUser{
		ID: f.ID, Name: common.FirstNonEmpty(f.Name, name), Email: f.Email, Provider: ID,
	}, nil
}
