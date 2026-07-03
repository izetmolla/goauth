# goauth providers

Providers describe **how a user proves who they are**. They are registered on `goauth.Config.Providers` and served by the sign-in / callback endpoints (see the [root README](../README.md#http-endpoints)).

## Available presets

| Provider | Package | Type | README |
|----------|---------|------|--------|
| Google | `providers/google` | OIDC (discovery, PKCE + state + nonce) | [google/README.md](google/README.md) |
| Azure AD / Entra ID | `providers/azuread` | OIDC v2.0 + Microsoft Graph profile | [azuread/README.md](azuread/README.md) |
| Credentials | `providers/credentials` | Username/password via custom `Authorize` | [credentials/README.md](credentials/README.md) |
| LDAP / Active Directory | `providers/ldap` | Directory bind + attribute/role mapping | [ldap/README.md](ldap/README.md) |

```go
auth, err := goauth.New(&goauth.Config{
	// ...
	Providers: []goauth.Provider{
		google.New(googleClientID, googleClientSecret),
		azuread.New(azuread.Options{ClientID: id, ClientSecret: secret, TenantID: tenant}),
		credentials.New(credentials.Options{Authorize: myAuthorizeFunc}),
	},
})
```

Each provider is reachable at:

```
GET/POST /api/authorization/provider/{id}            # start sign-in
GET/POST /api/authorization/provider/{id}/callback   # OAuth callback
```

and listed by `GET /api/authorization/providers`.

## The provider model

Every provider implements the small `goauth.Provider` interface:

```go
type Provider interface {
	ID() string          // unique, URL-safe id used in routes ("google")
	Name() string        // display name ("Google")
	Type() ProviderType  // oauth | oidc | credentials | email | passkey
}
```

Concrete implementations live in the root package:

- **`goauth.OAuthProvider`** — any OAuth 2.0 / OpenID Connect service. Endpoints can be set explicitly (`AuthorizationURL`, `TokenURL`, `UserInfoURL`) or discovered from an OIDC `Issuer` (`/.well-known/openid-configuration`). Security checks (`CheckPKCE`, `CheckState`, `CheckNonce`) are opt-in per provider.
- **`goauth.CredentialsProvider`** — arbitrary credentials validated by a user-supplied `Authorize` function.

## From provider profile to your user

OAuth providers return a raw profile (`goauth.Profile`, a `map[string]any`). Two mapping steps run on the callback:

1. **`Provider.Profile`** (per provider) normalizes the raw payload into a `goauth.OAuthUser` (id, email, name, avatar, ...). The presets ship a sensible default.
2. **`Config.ResolveUser`** (yours, required) receives the profile — enriched with `profile["provider"]` and `profile["providerType"]` — and returns the user from **your** database (`*goauth.User` with `ID` and `Roles`). This is where you look up or provision accounts.

After `ResolveUser` succeeds, goauth creates the session, signs the token pair, sets the session cookie, and renders the callback page.

## Writing a custom OAuth/OIDC provider

No special package is needed — construct an `OAuthProvider` directly:

```go
func GitHub(clientID, clientSecret string) goauth.Provider {
	return &goauth.OAuthProvider{
		ProviderID:       "github",
		DisplayName:      "GitHub",
		Kind:             goauth.ProviderOAuth,
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		AuthorizationURL: "https://github.com/login/oauth/authorize",
		TokenURL:         "https://github.com/login/oauth/access_token",
		UserInfoURL:      "https://api.github.com/user",
		Scopes:           []string{"read:user", "user:email"},
		Checks:           []goauth.Check{goauth.CheckState},
		Profile: func(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
			return &goauth.OAuthUser{
				ID:    common.String(p["id"]),
				Name:  common.String(p["name"]),
				Email: common.String(p["email"]),
				Image: common.String(p["avatar_url"]),
			}, nil
		},
	}
}
```

For OIDC services, set `Issuer` instead of the three endpoint URLs and goauth discovers them automatically.

Notes:

- `AuthorizationParams` (a `url.Values`) appends extra parameters to the authorize redirect (e.g. `prompt`, `access_type`).
- `AuthorizationStyle: "header"` sends client credentials as HTTP Basic to the token endpoint instead of in the form body.
- `TokenSet.Raw` preserves every non-standard field the token endpoint returned, so `Profile` can read provider-specific data.
- The `internal/common` package (`common.String`, `common.FirstNonEmpty`, `common.Values`) is only importable by packages under `providers/`; copy the helpers if you define providers elsewhere.
