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
	githubProvider(), // a custom goauth.OAuthProvider
	credentials.New(credentials.Options{ /* ... */ }),
},
```

| Provider | id | Type | Page |
|---|---|---|---|
| Google | `google` | `oidc` | [Google](./google.md) |
| Azure AD / Entra ID | `azuread-v2` | `oidc` | [Azure AD](./azure-ad.md) |
| Credentials | `credentials` (configurable) | `credentials` | [Credentials](./credentials.md) |
| LDAP / Active Directory | n/a (a client, not a provider) | n/a | [LDAP](./ldap.md) |
| Your own | anything | `oauth` / `oidc` | [Custom providers](../custom-providers/overview.md) |

## The `Provider` interface

```go
type Provider interface {
	ID() string               // URL-safe id used in routes, for example "github"
	Name() string             // display name, for example "GitHub"
	Type() goauth.ProviderType // "oauth", "oidc", "credentials", ...
}
```

The sign-in handlers understand two concrete types:

- `*goauth.OAuthProvider` for OAuth 2.0 and OpenID Connect
- `*goauth.CredentialsProvider` for form-based sign-in

Other types show up in `/providers` but their sign-in endpoint returns `400 Unsupported provider type`.

## Redirect URIs

Every OAuth provider needs this redirect URI registered at the identity provider:

```text
{AuthURL}/api/authorization/provider/{id}/callback
```

For example, `https://app.example.com/api/authorization/provider/google/callback`. Use `GET /api/authorization/providers` to see the exact `callbackUrl` values for your configuration.

## Multiple providers, one user

`ResolveUser` receives `profile["provider"]`, so you can link several providers to one user. See [One user, several providers](../guides/oauth-sign-in.md#one-user-several-providers).
