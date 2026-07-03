// Package google provides a Google sign-in provider for goauth using OpenID
// Connect discovery.
//
//	import "github.com/izetmolla/goauth/providers/google"
//
//	google.New(clientID, clientSecret)
package google

import (
	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

// New returns a configured Google provider using OpenID Connect discovery.
func New(clientID, clientSecret string) goauth.Provider {
	return &goauth.OAuthProvider{
		ProviderID:   "google",
		DisplayName:  "Google",
		Kind:         goauth.ProviderOIDC,
		Issuer:       "https://accounts.google.com",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "email", "profile"},
		Checks:       []goauth.Check{goauth.CheckPKCE, goauth.CheckState, goauth.CheckNonce},
		Profile: func(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
			return &goauth.OAuthUser{
				ID:    common.String(p["sub"]),
				Name:  common.String(p["name"]),
				Email: common.String(p["email"]),
				Image: common.String(p["picture"]),
			}, nil
		},
	}
}
