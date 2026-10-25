---
title: Core concepts
description: The Authorization object, providers, ResolveUser, sessions, tokens and the two protection modes.
---

# Core concepts

Read this page once. Every guide after it builds on these ideas.

## The `Authorization` object

`goauth.New` validates a `Config` and returns an `*goauth.Authorization`. Create it **once** at startup and share it: it is safe for concurrent use.

```go
auth, err := goauth.New(&goauth.Config{
	JWTSecret: os.Getenv("JWT_SECRET"), // required
	DB:        db,                      // required
	// everything else is optional
})
```

Everything else hangs off `auth`: the HTTP handlers, the middlewares, and helpers such as `auth.Authorize` and `auth.GetAuthDataAPI`.

## Providers

A provider is a way to sign in. goauth ships with:

| Provider | Type | Package |
|---|---|---|
| Google | OIDC | `providers/google` |
| Azure AD / Entra ID | OIDC | `providers/azuread` |
| Credentials | credentials | `providers/credentials` |
| Anything OAuth 2.0 / OIDC | oauth / oidc | `goauth.OAuthProvider` literal |

LDAP is a separate client (`providers/ldap`) that you call from your own login handler.

Each provider has an **id** used in URLs: `/api/authorization/provider/{id}`.

## `ResolveUser`: you own the users

goauth does not have a user model. After a provider confirms who someone is, goauth calls your `ResolveUser` with the raw provider profile (the userinfo JSON, for example Google's `sub`, `email`, `name`, `picture`). You find or create the user in your own table and return its id and roles:

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	u, err := users.FindOrCreateByEmail(ctx, p["email"].(string))
	if err != nil {
		return nil, false, err
	}
	return &goauth.User{ID: u.ID, Roles: u.Roles}, u.JustCreated, nil
}
```

goauth adds two keys to the profile before calling you: `provider` (for example `google`) and `providerType` (for example `oidc`).

## Sessions and tokens

A successful sign-in produces three things:

```text
            ┌─────────────────────────────┐
            │ sessions row (database)     │  id, user_id, expires_at, is_deleted ...
            └──────────────┬──────────────┘
                           │ session id
        ┌──────────────────┼────────────────────┐
        ▼                  ▼                    ▼
 refresh token (JWT)   session cookie       access token (JWT)
 long-lived (1y)       cnf.id=<session id>  short-lived (60s)
 carries session_id    for web pages        carries user_id + roles
```

| | Access token | Refresh token | Session cookie |
|---|---|---|---|
| Format | JWT (HS256 by default) | JWT | Opaque session id |
| Default lifetime | `60s` | `1y` | same as refresh token |
| Claims | `user_id`, `roles`, `content`, `token_type: access` | `session_id`, `user_id`, `roles`, `token_type: refresh` | none |
| Used by | `UseAPIAuthorization` | `HandleRefreshToken`, `CheckSession` | `UseWEBAuthorization` |
| Revocable | No: valid until it expires | Yes: checked against the session row | Yes: checked against the session row |

Because the access token cannot be revoked, keep it short-lived and refresh it with the refresh token. Signing out marks the session row `is_deleted = true`, which stops both the refresh token and the cookie.

The two token types are not interchangeable: a refresh token is rejected by the API middleware, and an access token is rejected by the refresh endpoint.

## Two ways to protect routes

| | `UseAPIAuthorization` | `UseWEBAuthorization` |
|---|---|---|
| For | JSON APIs, SPAs, mobile apps | Server-rendered pages |
| Credential | `Authorization: Bearer <access token>` (or `?access_token=`) | Session cookie |
| Database hit | None (stateless JWT check) | One session lookup per request (or Redis) |
| When unauthenticated | `401` JSON | `307` redirect to `SignInRedirectURL?redirectUrl=<original>` |
| When missing a role | `403` JSON | `403` JSON |

Both accept `auth.WithRoles(...)` and `auth.WithExcludedPaths(...)`.

## Request flow for OAuth sign-in

```text
Browser                     Your app (goauth)                     Provider
   │  GET /api/authorization/provider/google                          │
   │──────────────────────────▶│                                      │
   │                           │ set state / PKCE / nonce cookies     │
   │◀──────── 302 to provider ─│                                      │
   │─────────────────────────────────────────────────────────────────▶│ user signs in
   │◀──────────────── 302 to .../provider/google/callback?code=... ───│
   │──────────────────────────▶│                                      │
   │                           │ check state, exchange code ─────────▶│
   │                           │◀──────────────── tokens + userinfo ──│
   │                           │ ResolveUser(profile)                 │
   │                           │ create session, sign tokens          │
   │◀── HTML callback page ────│ set session cookie                   │
   │  saves tokens in localStorage, redirects (or notifies opener)    │
```

## Framework independence

All goauth handlers are `http.Handler` / `http.HandlerFunc`, and all middlewares have the type `goauth.Middleware`, which is `func(http.Handler) http.Handler`. Any framework that can wrap a standard handler can use goauth. See [Frameworks](../frameworks/net-http.mdx).

Next: the [Guides](../guides/configuration.md), starting with configuration.
