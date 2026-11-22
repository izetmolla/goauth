// Package workos provides a WorkOS sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/workos"
//
//	workos.New(workos.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//		Issuer:      "https://your-issuer.example",
//		Connection:  "CONNECTION_ID",
//	})
package workos

import (
	"net/url"
	"strings"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/workos.
const ID = "workos"

// Options configures the WorkOS provider.
type Options struct {
	ClientID     string
	ClientSecret string
	// Issuer is the base URL of the identity server (no trailing path required).
	Issuer string
	// Connection is the WorkOS connection id (optional when using organization).
	Connection          string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured WorkOS provider.
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
	if issuer == "" {
		issuer = strings.TrimRight("https://api.workos.com/", "/")
	}
	authParams := url.Values{}
	for k, vs := range o.AuthorizationParams {
		authParams[k] = append([]string{}, vs...)
	}
	if o.Connection != "" {
		authParams.Set("connection", o.Connection)
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "WorkOS",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    issuer + "/sso/authorize",
		TokenURL:            issuer + "/sso/token",
		UserInfoURL:         issuer + "/sso/profile",
		AuthorizationParams: authParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		AuthorizationStyle:  "body",
		Profile:             profile,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	raw := common.Map(p["raw_attributes"])
	image := ""
	if raw != nil {
		image = common.String(raw["picture"])
	}
	return &goauth.OAuthUser{
		ID:        common.String(p["id"]),
		Name:      strings.TrimSpace(common.String(p["first_name"]) + " " + common.String(p["last_name"])),
		Email:     common.String(p["email"]),
		FirstName: common.String(p["first_name"]),
		LastName:  common.String(p["last_name"]),
		Image:     image,
		Provider:  ID,
	}, nil
}
