---
title: Custom providers
description: When to write your own provider, what you need from the identity provider, and how this section is organized.
---

# Custom providers

goauth ships with Google and Azure AD, but **any OAuth 2.0 or OpenID Connect provider** can be added in a few lines: GitHub, GitLab, Keycloak, Okta, Auth0, Authentik, Zitadel, Discord, your company's own identity server, and more.

A custom provider is just a `*goauth.OAuthProvider` value in `Config.Providers`. Nothing else in goauth changes: sign-in, callback, sessions, tokens, roles and the middlewares all work the same.

```go
Providers: []goauth.Provider{
	google.New(googleID, googleSecret),
	&goauth.OAuthProvider{ /* your provider */ },
},
```

## Before you start

Collect these from your identity provider's developer console or documentation:

| You need | Example (GitHub) | Where it goes |
|---|---|---|
| Client ID and secret | `Iv1.8a61f9b3a7aba766`, `••••` | `ClientID`, `ClientSecret` |
| OIDC issuer **or** endpoint URLs | `https://github.com/login/oauth/authorize`, `.../access_token`, `https://api.github.com/user` | `Issuer`, or `AuthorizationURL` + `TokenURL` + `UserInfoURL` |
| Scopes | `read:user user:email` | `Scopes` |
| Userinfo JSON shape | `{"id": 1, "login": "jane", "email": ...}` | your `Profile` function |
| Supported security checks | PKCE, `state` | `Checks` |

And register this redirect URI at the provider:

```text
{AuthURL}/api/authorization/provider/{your provider id}/callback
```

## OAuth 2.0 or OpenID Connect?

| | OpenID Connect | Plain OAuth 2.0 |
|---|---|---|
| Examples | Google, Azure AD, Keycloak, Okta, Auth0, GitLab | GitHub, Discord, many in-house servers |
| How to tell | `{issuer}/.well-known/openid-configuration` returns JSON | no discovery document |
| Configuration | set `Issuer`; endpoints are discovered | set the three endpoint URLs |
| `Kind` | `goauth.ProviderOIDC` | `goauth.ProviderOAuth` |

## This section

1. **[Step by step](./step-by-step.md)**: add a provider to your app, field by field.
2. **[Reusable package](./reusable-package.md)**: wrap it in a `New(Options)` package like the built-in Google and Azure AD providers.
3. **[Testing](./testing.md)**: test the complete sign-in flow against a fake OAuth server, without a browser or network.
4. **[Examples](./examples.md)**: ready-made definitions for GitHub, Keycloak, Okta, Auth0 and more.
