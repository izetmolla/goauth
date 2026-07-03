package goauth

import (
	"context"
	"net/http"
	"net/url"
)

// ProviderType enumerates the kinds of providers, mirroring Auth.js.
type ProviderType string

const (
	ProviderOAuth       ProviderType = "oauth"
	ProviderOIDC        ProviderType = "oidc"
	ProviderEmail       ProviderType = "email"
	ProviderCredentials ProviderType = "credentials"
	ProviderPasskey     ProviderType = "passkey"
)

// Check is an OAuth security check performed during the authorization flow.
type Check string

const (
	CheckPKCE  Check = "pkce"
	CheckState Check = "state"
	CheckNonce Check = "nonce"
)

// PublicProvider is the JSON shape returned by the /providers endpoint, matching
// Auth.js so existing client SDKs can consume it.
type PublicProvider struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	SignInURL   string `json:"signinUrl"`
	CallbackURL string `json:"callbackUrl"`
}

// Provider is the common interface implemented by every provider. Concrete
// providers (OAuthProvider, CredentialsProvider, EmailProvider) are constructed
// via the providers subpackage and registered on Config.Providers.
type Provider interface {
	// ID is the unique, URL-safe identifier used in routes (e.g. "github").
	ID() string
	// Name is the human-readable display name (e.g. "GitHub").
	Name() string
	// Type categorizes the provider.
	Type() ProviderType
}

// OAuthProvider describes an OAuth 2.0 or OpenID Connect provider. Endpoints can
// be specified explicitly or discovered from an OIDC Issuer.
type OAuthProvider struct {
	ProviderID   string
	DisplayName  string
	Kind         ProviderType // ProviderOAuth or ProviderOIDC
	ClientID     string
	ClientSecret string

	// Issuer enables OIDC discovery of authorization/token/userinfo/jwks URLs.
	Issuer string

	AuthorizationURL    string
	AuthorizationParams url.Values
	TokenURL            string
	UserInfoURL         string

	Scopes []string
	Checks []Check

	// Profile maps the raw provider profile (and tokens) into a User. Required.
	Profile func(profile Profile, tokens TokenSet) (*OAuthUser, error)

	// AuthorizationStyle controls how client credentials are sent to the token
	// endpoint: "body" (default) or "header" (HTTP Basic).
	AuthorizationStyle string
}

func (p *OAuthProvider) ID() string   { return p.ProviderID }
func (p *OAuthProvider) Name() string { return p.DisplayName }
func (p *OAuthProvider) Type() ProviderType {
	if p.Kind == "" {
		return ProviderOAuth
	}
	return p.Kind
}

// CredentialField describes a single input of a credentials form, mirroring the
// Auth.js `credentials` map.
type CredentialField struct {
	Name        string `json:"name"`
	Label       string `json:"label,omitempty"`
	Type        string `json:"type,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
}

// CredentialsProvider authenticates with arbitrary credentials via a
// user-supplied Authorize function. Sessions for credentials providers always
// use the JWT strategy, exactly as in Auth.js.
type CredentialsProvider struct {
	ProviderID  string
	DisplayName string
	Fields      []CredentialField
	// Authorize validates credentials and returns the signed-in user, or nil to
	// reject. Return credentials.SigninFailed (or goauth.CredentialsSigninFailed)
	// for field-level errors; (nil, nil) yields a generic invalid credentials
	// response.
	//
	// To require a one-time code for this sign-in, set user.RequireMFA = true and
	// user.MFADelivery (or use credentials.RequireMFA). MFAConfig.SendCode must be
	// configured; MFAConfig.Enabled can stay false for selective MFA only.
	Authorize func(ctx context.Context, credentials map[string]string, r *http.Request) (*OAuthUser, error)
}

func (p *CredentialsProvider) ID() string         { return p.ProviderID }
func (p *CredentialsProvider) Name() string       { return p.DisplayName }
func (p *CredentialsProvider) Type() ProviderType { return ProviderCredentials }

// findProvider returns the configured provider by id.
func (a *Authorization) findProvider(id string) Provider {
	if a == nil {
		return nil
	}
	for _, p := range a.providers {
		if p != nil && p.ID() == id {
			return p
		}
	}
	return nil
}
