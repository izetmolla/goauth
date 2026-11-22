package goauth

import (
	"context"
	"net/http"
	"net/url"
)

// ProviderType enumerates the kinds of providers, mirroring Auth.js.
type ProviderType string

// Provider types. The sign-in handlers support ProviderOAuth, ProviderOIDC,
// ProviderCredentials and ProviderPasskey; ProviderEmail is reserved.
const (
	ProviderOAuth       ProviderType = "oauth"
	ProviderOIDC        ProviderType = "oidc"
	ProviderEmail       ProviderType = "email"
	ProviderCredentials ProviderType = "credentials"
	ProviderPasskey     ProviderType = "passkey"
)

// Check is an OAuth security check performed during the authorization flow.
type Check string

// Security checks an OAuthProvider can enable in Checks.
const (
	// CheckPKCE sends an S256 code challenge and proves it with the verifier
	// at the token endpoint (RFC 7636).
	CheckPKCE Check = "pkce"
	// CheckState binds the callback to the browser that started the flow.
	CheckState Check = "state"
	// CheckNonce sends a random nonce and requires the ID token to echo it.
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
	// UserInfoMethod is the HTTP method for UserInfoURL. Empty means GET.
	UserInfoMethod string

	Scopes []string
	Checks []Check

	// Profile maps the raw provider profile (and tokens) into a User. Required.
	Profile func(profile Profile, tokens TokenSet) (*OAuthUser, error)

	// FetchUserInfo optionally replaces the default UserInfoURL request
	// (e.g. providers that need POST bodies or secondary API calls).
	FetchUserInfo func(ctx context.Context, tokens TokenSet) (Profile, error)

	// AuthorizationStyle controls how client credentials are sent to the token
	// endpoint: "body" (default) or "header" (HTTP Basic).
	AuthorizationStyle string
}

// ID implements Provider.
func (p *OAuthProvider) ID() string { return p.ProviderID }

// Name implements Provider.
func (p *OAuthProvider) Name() string { return p.DisplayName }

// Type implements Provider. It returns ProviderOAuth when Kind is empty.
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
	// Authenticator-app MFA is configured globally via Config.MFA.TOTP (off by
	// default). When enabled and the user has enrolled, finishSignIn challenges
	// with MFA_REQUIRED before creating a session — see the MFA TOTP guide.
	Authorize func(ctx context.Context, credentials map[string]string, r *http.Request) (*OAuthUser, error)

	// Register creates an account from the sign-up form and returns the new
	// user, who is then signed in. Leave nil to disable sign-up for this
	// provider. Return a *CredentialsError for a message the user should see
	// (for example "That email is already registered").
	Register func(ctx context.Context, fields map[string]string, r *http.Request) (*OAuthUser, error)

	// RegisterFields are the sign-up form inputs. Default: Fields.
	RegisterFields []CredentialField
}

// Input types (and default field names) used by credentials forms.
const (
	inputText     = "text"
	inputEmail    = "email"
	inputPassword = "password"
	inputTel      = "tel"
)

// payloadType is the key that tells the callback page which flow finished.
const payloadType = "type"

// defaultCredentialFields is the form used when a provider declares none.
var defaultCredentialFields = []CredentialField{
	{Name: inputEmail, Label: "Email", Type: inputEmail, Placeholder: "you@example.com"},
	{Name: inputPassword, Label: "Password", Type: inputPassword},
}

func (p *CredentialsProvider) signInFields() []CredentialField {
	if len(p.Fields) > 0 {
		return p.Fields
	}
	return defaultCredentialFields
}

func (p *CredentialsProvider) registerFields() []CredentialField {
	if len(p.RegisterFields) > 0 {
		return p.RegisterFields
	}
	return p.signInFields()
}

// ID implements Provider.
func (p *CredentialsProvider) ID() string { return p.ProviderID }

// Name implements Provider.
func (p *CredentialsProvider) Name() string { return p.DisplayName }

// Type implements Provider.
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
