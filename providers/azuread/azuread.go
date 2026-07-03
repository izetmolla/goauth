// Package azuread provides a Microsoft Azure Active Directory (Entra ID)
// sign-in provider for goauth using the v2.0 OAuth / OIDC endpoints.
//
//	import "github.com/izetmolla/goauth/providers/azuread"
//
//	azuread.New(azuread.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//		TenantID:     "YOUR_TENANT_ID",
//	})
package azuread

import (
	"fmt"
	"net/url"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const (
	authURLTemplate  = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
	tokenURLTemplate = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	userInfoURL      = "https://graph.microsoft.com/v1.0/me"
)

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{
	"openid", "profile", "email", "User.Read",
	// "Files.Read",
	// "Files.ReadWrite",
	// "Mail.Read",
	// "Mail.Send",
}

// Options configures the Azure AD provider.
type Options struct {
	// ClientID is the Application (client) ID from the Azure portal.
	ClientID string
	// ClientSecret is the client secret generated in the Azure portal.
	ClientSecret string
	// TenantID controls which accounts may sign in. Accepted values:
	//   - a tenant GUID         → single-tenant (your organisation only)
	//   - "common"              → any Azure AD or personal Microsoft account
	//   - "organizations"       → any Azure AD account
	//   - "consumers"           → personal Microsoft accounts only
	// Defaults to "common" when empty.
	TenantID string
	// Scopes override the default set (openid, profile, email, User.Read).
	// Set this to add or remove Microsoft Graph permissions.
	Scopes []string
	// AuthorizationParams are appended to the OAuth authorize request.
	AuthorizationParams url.Values
	// Profile optionally overrides the default user-mapping function.
	Profile func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Azure AD provider.
func New(o Options) goauth.Provider {
	tenant := o.TenantID
	if tenant == "" {
		tenant = "common"
	}
	scopes := o.Scopes
	if scopes == nil {
		scopes = DefaultScopes
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	return &goauth.OAuthProvider{
		ProviderID:          "azuread-v2",
		DisplayName:         "Azure Active Directory",
		Kind:                goauth.ProviderOIDC,
		Issuer:              fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenant),
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    fmt.Sprintf(authURLTemplate, tenant),
		TokenURL:            fmt.Sprintf(tokenURLTemplate, tenant),
		UserInfoURL:         userInfoURL,
		Scopes:              scopes,
		AuthorizationParams: o.AuthorizationParams,
		Checks:              []goauth.Check{goauth.CheckPKCE, goauth.CheckState, goauth.CheckNonce},
		Profile:             profile,
	}
}

// DefaultProfile maps Azure AD / Microsoft Graph claims to a goauth.User.
// It handles both OIDC id_token claims and Graph API response fields.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	return &goauth.OAuthUser{
		ID:        common.FirstNonEmpty(common.String(p["sub"]), common.String(p["id"]), common.String(p["oid"])),
		Name:      common.FirstNonEmpty(common.String(p["name"]), common.String(p["displayName"])),
		Email:     common.FirstNonEmpty(common.String(p["email"]), common.String(p["mail"]), common.String(p["userPrincipalName"])),
		FirstName: common.String(p["givenName"]),
		LastName:  common.String(p["surname"]),
		Image:     common.String(p["picture"]),
		Provider:  "azuread-v2",
	}, nil
}
