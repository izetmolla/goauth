---
title: HTTP endpoints
description: The routes served by auth.Handler(), their parameters and responses.
---

# HTTP endpoints

`auth.Handler()` returns one `http.Handler` that serves every goauth route under `goauth.DefaultBasePath` (`/api/authorization`):

| Method | Path | Handler | Purpose |
|---|---|---|---|
| `GET` | `/api/authorization/providers` | `auth.GetProviders` | List configured providers as JSON |
| any | `/api/authorization/provider/{id}` | `auth.HandleSignIn` | Start sign-in |
| any | `/api/authorization/provider/{id}/callback` | `auth.HandleCallback` | OAuth callback |
| `POST` | `/api/authorization/provider/{id}/register` | `auth.HandleRegister` | Credentials sign-up (off by default) |
| `POST` | `/api/authorization/provider/passkey/{register\|login}/{begin\|finish}` | `auth.HandlePasskey` | Passkey ceremonies when a passkey provider is registered ([passkey](../providers/passkey.md)) |
| `GET` | `/api/authorization/register` (`UI.RegisterEndpoint`) | `auth.RegisterPage` | Sign-up page (off by default) |
| | `/forgot`, `/password/*`, `/otp*`, `/verify-email*` | | Password reset, one-time codes, email confirmation (off by default, see [verification](./verification.md#4-endpoints)) |
| `GET`/`POST` | `/api/authorization/mfa/totp/*` | `auth.HandleTOTPStatus`, … | Authenticator MFA (off by default, see [MFA TOTP](./mfa-totp.md)) |
| `GET`/`POST` | `/api/authorization/login_as?user_id=` | `auth.HandleLoginAs` | Admin login-as (off by default, see [Login as](./login-as.md)) |
| `GET` | `/api/authorization/csrf` | `auth.GetCSRFToken` | CSRF token for custom forms |
| `POST` | `/api/authorization/signout` | `auth.HandleSignOut` | Revoke the current session and clear its cookie ([Sign-out](./sign-out.md)) |
| `GET` | `/api/authorization/signin` (`UI.SignInEndpoint`) | `auth.SignInPage` | Built-in sign-in page, off by default ([details](./sign-in-page.md)) |
| `GET` | `/api/authorization/assets/{file}` | | The page's CSS and JS |

Sign-in APIs are on by default. Sign-up, verification, MFA, login-as and every HTML page are off until enabled, and the pages can be served at your own paths (`UI.SignInEndpoint` and friends). See [Built-in pages](./sign-in-page.md#switching-parts-on-and-off).

### MFA routes (when `MFA.TOTP.Enabled`)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/authorization/mfa/totp/status` | Whether the signed-in user has TOTP enabled |
| `POST` | `/api/authorization/mfa/totp/enroll/begin` | Start enrollment (otpauth URL + secret) |
| `POST` | `/api/authorization/mfa/totp/enroll/confirm` | Confirm with first code; returns backup codes |
| `POST` | `/api/authorization/mfa/totp/disable` | Turn off TOTP (code or backup) |
| `POST` | `/api/authorization/mfa/totp/verify` | Complete sign-in after `MFA_REQUIRED` |

### Login-as (when `LoginAs.Enabled`)

| Method | Path | Purpose |
|---|---|---|
| `GET` or `POST` | `/api/authorization/login_as?user_id=` | Impersonate another user (admin session required) |

## Mounting

Mount it on the base path with a trailing wildcard:

```go
// net/http
mux.Handle(goauth.DefaultBasePath+"/", auth.Handler())

// Fiber
app.All(goauth.DefaultBasePath+"/*", adaptor.HTTPHandler(auth.Handler()))

// Echo
e.Any(goauth.DefaultBasePath+"/*", echo.WrapHandler(auth.Handler()))

// Gin
r.Any(goauth.DefaultBasePath+"/*path", gin.WrapH(auth.Handler()))

// Chi
r.Mount(goauth.DefaultBasePath, auth.Handler())
```

:::note
The handler matches the full request path, so mount it so the router passes the **unchanged** path. Do not use `http.StripPrefix` in front of it.
:::

### Registering routes yourself

The three handlers are exported as `http.HandlerFunc`-compatible methods:

```go
mux.HandleFunc("GET /auth/providers", auth.GetProviders)
mux.HandleFunc("/auth/provider/{provider}", auth.HandleSignIn)
mux.HandleFunc("/auth/provider/{provider}/callback", auth.HandleCallback)
```

The `{provider}` segment is read from `r.PathValue("provider")`. When your router doesn't set it, goauth falls back to the path segment after `/provider/`.

:::caution
OAuth redirect URIs are always built from `DefaultBasePath`. If you mount the routes somewhere else, change `goauth.DefaultBasePath` at startup so the callback URL matches:

```go
goauth.DefaultBasePath = "/auth"
```
:::

## `GET /providers`

Returns the providers in configuration order, in the same JSON shape as Auth.js:

```bash
curl http://localhost:3000/api/authorization/providers
```

```json
[
  {
    "id": "google",
    "name": "Google",
    "type": "oidc",
    "signinUrl": "http://localhost:3000/api/authorization/provider/google",
    "callbackUrl": "http://localhost:3000/api/authorization/provider/google/callback"
  },
  {
    "id": "azuread-v2",
    "name": "Azure Active Directory",
    "type": "oidc",
    "signinUrl": "http://localhost:3000/api/authorization/provider/azuread-v2",
    "callbackUrl": "http://localhost:3000/api/authorization/provider/azuread-v2/callback"
  }
]
```

Use it to render sign-in buttons dynamically.

## `/provider/{id}`: start sign-in

For OAuth / OIDC providers, this:

1. Runs OIDC discovery when needed.
2. Clears leftover cookies from earlier attempts.
3. Sets short-lived (15 minute) cookies for `state`, the PKCE verifier and `nonce`, for each check the provider enables.
4. Redirects (`302`) to the provider's authorization URL.

Query parameters:

| Parameter | Effect |
|---|---|
| `json=true` | Return `{"url": "<authorization URL>"}` instead of a redirect |
| `callbackUrl=<url>` | Store a post-sign-in target in the `authjs.callback-url` cookie for your own code to read (the built-in callback page does not use it yet) |
| `connect=1` | Start a [provider connect](./provider-connect.md) flow instead of a sign-in |
| `resource_id=<uuid>` | With `connect=1`: the record to link the account to |

The JSON response is also returned when the request has `Accept: application/json` or `X-Auth-Return-Redirect: 1`:

```bash
curl -H 'Accept: application/json' \
  http://localhost:3000/api/authorization/provider/google
```

```json
{"url":"https://accounts.google.com/o/oauth2/v2/auth?client_id=...&code_challenge=...&state=..."}
```

For **credentials** providers the endpoint only accepts `POST` and checks CSRF. See [Credentials sign-in](./credentials-login.md) for the recommended way to build password sign-in.

## `/provider/{id}/callback`

The provider redirects the browser here. goauth:

1. Clears all short-lived flow cookies.
2. Merges query and `POST` form fields (for `response_mode=form_post` providers such as Sign in with Apple).
3. Rejects provider errors, a missing `code`, or a `state` mismatch.
4. Exchanges the code for tokens (sending the PKCE verifier) and fetches userinfo.
5. Calls the provider's `Profile` mapper, then your `ResolveUser`.
6. **Sign-in**: creates a session, signs the token pair, sets the session cookie.
   **Connect**: calls `OnProviderConnect` instead.
7. Renders a small HTML page (see [the callback page](./oauth-sign-in.md#the-callback-page)).

Errors are shown on the same page, never as raw JSON, because the user is looking at a browser tab.

## Status codes

| Situation | Status | Body |
|---|---|---|
| Unknown provider id | `404` | `{"message":"Unknown provider: x","code":"ERROR"}` |
| Credentials provider with non-POST | `405` | `{"message":"Credentials sign-in requires POST","code":"ERROR"}` |
| Bad CSRF token | `403` | `{"message":"Invalid CSRF token","code":"ERROR"}` |
| OIDC discovery or config failure | `500` | `{"message":"Discovery failed","code":"ERROR"}` |
| Callback failures | `200` | HTML page in error state |

Error responses use a JSON body with an `error` field and an appropriate HTTP status.
