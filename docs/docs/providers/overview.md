---
title: Providers overview
description: The provider types goauth supports and how they are registered.
---

# Providers overview

Providers are registered in `Config.Providers`. Their order is the order returned by `GET /api/authorization/providers`.

```go
Providers: []goauth.Provider{
	google.New(googleID, googleSecret),
	azuread.New(azuread.Options{ClientID: azID, ClientSecret: azSecret, TenantID: tenant}),
	github.New(github.Options{ClientID: ghID, ClientSecret: ghSecret}),
	credentials.New(credentials.Options{ /* ... */ }),
},
```

## Featured guides

| Provider | id | Type | Page |
|---|---|---|---|
| Google | `google` | `oidc` | [Google](./google.md) |
| Azure AD / Entra ID | `azuread-v2` | `oidc` | [Azure AD](./azure-ad.md) |
| Credentials | `credentials` (configurable) | `credentials` | [Credentials](./credentials.md) |
| Passkey | `passkey` | WebAuthn | [Passkey](./passkey.md) |

## All OAuth / OIDC presets

Every Auth.js-style preset ships under `providers/<package>` with a usage page:

**[Browse all presets →](./presets/catalog.md)**

Each page shows import path, `New(Options)` example, provider `id`, default scopes, endpoints, and redirect URI.

Redirect URI pattern:

```text
{AuthURL}/api/authorization/provider/{id}/callback
```

Second-factor **TOTP** is not a provider — configure `Config.MFA.TOTP` ([guide](../guides/mfa-totp.md)).

## The `Provider` interface

```go
type Provider interface {
	ID() string               // URL-safe id used in routes, for example "github"
	Name() string             // display name, for example "GitHub"
	Type() goauth.ProviderType // "oauth", "oidc", "credentials", ...
}
```

The sign-in handlers understand:

- `*goauth.OAuthProvider` for OAuth 2.0 and OpenID Connect
- `*goauth.CredentialsProvider` for form-based sign-in
- `*goauth.PasskeyProvider` for WebAuthn (from `providers/passkey`)

Other types show up in `/providers` but their generic sign-in endpoint returns `400 Unsupported provider type` (passkeys use dedicated begin/finish routes).

## Redirect URIs

Every OAuth provider needs this redirect URI registered at the identity provider:

```text
{AuthURL}/api/authorization/provider/{id}/callback
```

For example, `https://app.example.com/api/authorization/provider/google/callback`. Use `GET /api/authorization/providers` to see the exact `callbackUrl` values for your configuration.

## Multiple providers, one user

`ResolveUser` receives `profile["provider"]`, so you can link several providers to one user. See [One user, several providers](../guides/oauth-sign-in.md#one-user-several-providers).

## Writing your own

See [Custom providers](../custom-providers/overview.md) to wrap any OAuth 2.0 / OIDC server with a plain `goauth.OAuthProvider`.
