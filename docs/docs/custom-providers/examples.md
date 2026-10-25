---
title: Examples
description: Ready-made OAuthProvider definitions for GitHub, Keycloak, Okta, Auth0 and providers with HTTP Basic client auth.
---

# Custom provider examples

Copy-paste definitions for common providers. For what each field means, follow the [step-by-step guide](./step-by-step.md).

## Example: GitHub (plain OAuth 2.0)

GitHub is not an OIDC provider, so its endpoints are explicit:

```go
func githubProvider() *goauth.OAuthProvider {
	return &goauth.OAuthProvider{
		ProviderID:       "github",
		DisplayName:      "GitHub",
		Kind:             goauth.ProviderOAuth,
		ClientID:         os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret:     os.Getenv("GITHUB_CLIENT_SECRET"),
		AuthorizationURL: "https://github.com/login/oauth/authorize",
		TokenURL:         "https://github.com/login/oauth/access_token",
		UserInfoURL:      "https://api.github.com/user",
		Scopes:           []string{"read:user", "user:email"},
		Checks:           []goauth.Check{goauth.CheckState, goauth.CheckPKCE},
		Profile: func(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
			id, _ := p["id"].(float64) // JSON numbers decode as float64
			login, _ := p["login"].(string)
			name, _ := p["name"].(string)
			email, _ := p["email"].(string)
			avatar, _ := p["avatar_url"].(string)
			return &goauth.OAuthUser{
				ID:       strconv.FormatInt(int64(id), 10),
				NickName: login,
				Name:     cmp.Or(name, login),
				Email:    email,
				Image:    avatar,
			}, nil
		},
	}
}
```

Register the callback URL `https://app.example.com/api/authorization/provider/github/callback` in **GitHub → Settings → Developer settings → OAuth Apps**.

GitHub's `email` is `null` when the user hides it. In `ResolveUser`, fall back to the GitHub `id`, or call `https://api.github.com/user/emails` with the access token from the `Account`.

## Example: Keycloak (OIDC discovery)

```go
&goauth.OAuthProvider{
	ProviderID:   "keycloak",
	DisplayName:  "Company SSO",
	Kind:         goauth.ProviderOIDC,
	Issuer:       "https://sso.example.com/realms/acme",
	ClientID:     os.Getenv("KEYCLOAK_CLIENT_ID"),
	ClientSecret: os.Getenv("KEYCLOAK_CLIENT_SECRET"),
	Scopes:       []string{"openid", "email", "profile"},
	Checks:       []goauth.Check{goauth.CheckPKCE, goauth.CheckState, goauth.CheckNonce},
	Profile: func(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
		sub, _ := p["sub"].(string)
		email, _ := p["email"].(string)
		name, _ := p["name"].(string)
		return &goauth.OAuthUser{ID: sub, Email: email, Name: name}, nil
	},
}
```

goauth fetches `{Issuer}/.well-known/openid-configuration` on the first sign-in and fills in the endpoints. Discovery is guarded by a mutex, so concurrent first requests are safe.

The same pattern works for Okta (`https://dev-123.okta.com/oauth2/default`), Auth0 (`https://tenant.eu.auth0.com/`), GitLab (`https://gitlab.com`), Authentik, Zitadel and other OIDC providers.

## Example: a provider that requires HTTP Basic client auth

```go
&goauth.OAuthProvider{
	ProviderID:         "acme",
	DisplayName:        "Acme",
	Kind:               goauth.ProviderOAuth,
	ClientID:           os.Getenv("ACME_CLIENT_ID"),
	ClientSecret:       os.Getenv("ACME_CLIENT_SECRET"),
	AuthorizationURL:   "https://id.acme.com/oauth/authorize",
	TokenURL:           "https://id.acme.com/oauth/token",
	UserInfoURL:        "https://api.acme.com/v1/me",
	AuthorizationStyle: "header",
	Checks:             []goauth.Check{goauth.CheckState},
	Profile:            acmeProfile,
}
```

## Providers without a userinfo endpoint

If `UserInfoURL` is empty (and discovery doesn't provide one), `Profile` gets an empty profile. Decode the claims from `tokens.IDToken` or `tokens.Raw` yourself:

```go
Profile: func(_ goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error) {
	claims, err := verifyIDToken(tokens.IDToken) // verify signature with the provider's JWKS
	if err != nil {
		return nil, err
	}
	return &goauth.OAuthUser{ID: claims.Subject, Email: claims.Email}, nil
},
```

`ResolveUser` would then receive an empty profile too (plus `provider` and `providerType`), so prefer providers with a userinfo endpoint, or look the user up by the `Account` instead.

## Token response handling

- JSON and form-encoded (`application/x-www-form-urlencoded`) token responses are both supported.
- `expires_in` is converted to an absolute `Account.ExpiresAt` (Unix seconds).
- Every field of the token response is kept in `TokenSet.Raw`, so non-standard values are available in `Profile`.
- Provider responses are capped at 1 MiB.
