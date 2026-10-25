---
title: Cookies
description: Every cookie goauth sets, its secure defaults, and how to override names, domains and lifetimes.
---

# Cookies

## Cookies goauth sets

| Purpose | Name on HTTP | Name on HTTPS | Lifetime |
|---|---|---|---|
| Web session | `cnf.id` | `cnf.id` | `RefreshTokenDuration` |
| OAuth `state` | `authjs.state` | `__Secure-authjs.state` | 15 min |
| PKCE verifier | `authjs.pkce.code_verifier` | `__Secure-authjs.pkce.code_verifier` | 15 min |
| OIDC `nonce` | `authjs.nonce` | `__Secure-authjs.nonce` | 15 min |
| Callback URL | `authjs.callback-url` | `__Secure-authjs.callback-url` | browser session |
| CSRF token | `authjs.csrf-token` | `__Host-authjs.csrf-token` | browser session |
| Flow mode | `authjs.flow` | `__Secure-authjs.flow` | 15 min |
| Connect intent | `authjs.flow-intent` | `__Secure-authjs.flow-intent` | 15 min |
| Connect resource | `authjs.connect-resource` | `__Secure-authjs.connect-resource` | 15 min |

All of them are `HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure` on HTTPS. The names follow Auth.js.

"HTTPS" means `AuthURL` starts with `https://`, or, when `AuthURL` is empty, the request arrived over TLS or with `X-Forwarded-Proto: https`.

:::info[Why `SameSite=Lax`]
The OAuth callback is a top-level navigation coming from the provider's site. `Lax` cookies are sent on such navigations, while `Strict` would drop the `state` and PKCE cookies and break sign-in.
:::

## Overriding cookies

Use `Config.Cookies` to change individual cookies. Only the fields you set are changed; the rest keep their secure defaults:

```go
auth, err := goauth.New(&goauth.Config{
	JWTSecret:         os.Getenv("JWT_SECRET"),
	DB:                db,
	CookieSessionName: "myapp_session",
	Cookies: &goauth.CookieOptions{
		SessionToken: &goauth.CookieOption{
			MaxAge:   30 * 24 * time.Hour,
			SameSite: http.SameSiteStrictMode,
		},
	},
})
```

| `CookieOption` field | Effect when set |
|---|---|
| `Name` | Replaces the cookie name |
| `Path` | Replaces the path |
| `Domain` | Sets the `Domain` attribute (cross-subdomain sharing) |
| `SameSite` | Replaces `SameSite` |
| `MaxAge` | Replaces the lifetime |
| `HTTPOnly`, `Secure` | Can only be turned **on**; overrides never weaken the defaults |

Overridable cookies: `SessionToken`, `CallbackURL`, `CSRFToken`, `PKCECodeVerifier`, `State`, `Nonce`.

:::warning
Don't set `SameSite: http.SameSiteStrictMode` on `State`, `PKCECodeVerifier` or `Nonce`: the OAuth callback would lose them. Strict is fine for the session cookie if users always enter your site by navigating within it.
:::

## Sharing cookies across subdomains

```go
cookies := goauth.CrossSubdomainCookies(".example.com")
auth, err := goauth.New(&goauth.Config{
	// ...
	Cookies: &cookies,
})
```

This sets `Domain=.example.com` on every cookie. The CSRF cookie switches from the `__Host-` to the `__Secure-` prefix, because `__Host-` cookies cannot have a `Domain`. See [Cross-subdomain SSO](./cross-subdomain-sso.md).

## Reading and writing the session cookie

```go
id := auth.GetSessionID(r)           // "" when absent
auth.SetSessionIDCookie(w, r, newID) // after Authorize
```

## Local development over HTTP

On `http://localhost`, cookies have no prefix and no `Secure` flag, so everything works without TLS. Browsers treat `localhost` as a secure context, so `__Secure-` cookies also work there if you use `https://localhost`.

Use the **same host** throughout development: cookies set on `localhost` are not sent to `127.0.0.1`.
