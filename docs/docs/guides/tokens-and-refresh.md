---
title: Tokens and refresh
description: Access and refresh token lifetimes, claims, the refresh endpoint, CheckSession and issuing tokens yourself.
---

# Tokens and refresh

## The token pair

Every sign-in returns two JWTs, signed with `JWTSecret`:

```json
{"access_token": "eyJ...", "refresh_token": "eyJ..."}
```

**Access token** claims:

```json
{
  "user_id": "5b1c2f7e-...",
  "token_type": "access",
  "roles": ["admin:rw"],
  "content": {},
  "exp": 1793000060,
  "iat": 1793000000
}
```

**Refresh token** claims:

```json
{
  "session_id": "3f0c9a51-...",
  "user_id": "5b1c2f7e-...",
  "token_type": "refresh",
  "tokenlife": "1m0s",
  "signing_method": "HS256",
  "roles": ["admin:rw"],
  "exp": 1824536000,
  "iat": 1793000000
}
```

| | Default | Config field |
|---|---|---|
| Access token lifetime | `60s` | `AccessTokenDuration` |
| Refresh token lifetime | `1y` | `RefreshTokenDuration` |

A good production starting point is `AccessTokenDuration: "15m"` and `RefreshTokenDuration: "30d"`.

## The refresh endpoint

`auth.HandleRefreshToken(next)` is a middleware that answers refresh requests. It only acts when the request carries the opt-in header **`cft`** (`goauth.RefreshTokenHandlerIdentifier`) with any value except empty or `no`. Every other request goes to `next`.

```go
fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "missing cft header", http.StatusBadRequest)
})
mux.Handle("POST /api/token/refresh", auth.HandleRefreshToken(fallback))
```

The opt-in header lets you put the middleware in front of an existing route, or in front of the whole app, without it intercepting normal traffic:

```go
// Any request with "cft: 1" is treated as a refresh request.
http.ListenAndServe(":3000", auth.HandleRefreshToken(mux))
```

### Request

Send the refresh token in the `Authorization` header (`Bearer` or `Token` scheme, or the bare token):

```bash
curl -X POST https://app.example.com/api/token/refresh \
  -H "cft: 1" \
  -H "Authorization: Bearer <refresh_token>"
```

or in a JSON body:

```bash
curl -X POST https://app.example.com/api/token/refresh \
  -H "cft: 1" -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

### Response

On success the body is the new access token as a JSON **string**:

```json
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

The refresh token is not rotated; keep using the same one until it expires.

What the endpoint checks:

1. The refresh token is valid, unexpired, and really a refresh token.
2. Its session exists, is not signed out, and has not expired.
3. The token's `user_id` matches the session owner.

The new access token contains the user's **current** roles from the database.

### Errors

| Situation | Status | `code` |
|---|---|---|
| No refresh token sent | `401` | `TOKEN_INVALID` |
| Bad signature, expired, or an access token | `401` | `TOKEN_INVALID` |
| Session signed out, missing, or expired | `401` | `UNAUTHORIZED` |
| Database failure | `500` | `SERVER_ERROR` |

```json
{"error":"authorization: invalid refresh token: token has invalid claims: token is expired","code":"TOKEN_INVALID"}
```

On any `401`, send the user back to sign-in.

## Refreshing from a JavaScript client

Wrap `fetch` so an expired access token is renewed once and the request retried:

```js
let accessToken = null;
let refreshToken = null;

async function refresh() {
  const res = await fetch('/api/token/refresh', {
    method: 'POST',
    headers: {cft: '1', Authorization: `Bearer ${refreshToken}`},
  });
  if (!res.ok) throw new Error('session expired');
  accessToken = await res.json(); // body is a JSON string
}

export async function api(path, init = {}) {
  const send = () =>
    fetch(path, {...init, headers: {...init.headers, Authorization: `Bearer ${accessToken}`}});
  let res = await send();
  if (res.status === 401) {
    await refresh();
    res = await send();
  }
  return res;
}
```

Use the patterns on this page to build a SPA client with multiple accounts and popup sign-in.

## `CheckSession`: restore a web session from a refresh token

`auth.CheckSession(w, r)` does the same validation as the refresh endpoint, **and** sets the session cookie. Use it when a browser holds a refresh token (for example in `localStorage`) but has no session cookie, such as on a new subdomain:

```go
mux.HandleFunc("POST /api/session", func(w http.ResponseWriter, r *http.Request) {
	res, err := auth.CheckSession(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"session_id": res.SessionID,
		"user_id":    res.UserID,
		"tokens":     res.Tokens, // fresh access token + the same refresh token
	})
})
```

Errors are the package errors (`goauth.ErrMissingRefreshToken`, `goauth.ErrInvalidRefreshToken`, `goauth.ErrSessionNotFound`, `goauth.ErrSessionExpired`), so you can match them with `errors.Is`.

## Issuing tokens yourself with `Authorize`

`auth.Authorize` creates a session row and signs a token pair. Use it whenever **your** code has verified a user, for example password sign-in, LDAP, magic links or impersonation:

```go
tokens, sessionID, err := auth.Authorize(
	auth.WithUserID(user.ID),
	auth.WithContext(r.Context()),
	auth.WithIPAddress(r.RemoteAddr),
	auth.WithUserAgent(r.UserAgent()),
	auth.WithMethod("password"),
)
```

Or capture all request metadata at once:

```go
opts := append([]goauth.AuthorizeOptionsFunc{auth.WithUserID(user.ID)},
	auth.SessionMetaFromRequest(r, "password")...)
tokens, sessionID, err := auth.Authorize(opts...)
```

| Option | Stored on |
|---|---|
| `WithUserID(id)` | token `user_id`, session `user_id`; roles are loaded from the users table for this id |
| `WithUserRoles(roles)` | token `roles`, used only when the user row cannot be read (roles in the users table always win) |
| `WithAccount(*goauth.Account)` | session `account` (provider tokens) |
| `WithContext(ctx)` | used for the database calls |
| `WithIPAddress(ip)` | session `ip_address` |
| `WithUserAgent(ua)` | session `user_agent` |
| `WithMethod(m)` | session `method` (default `credentials`) |

Then give the tokens to the client and, for browser pages, set the cookie:

```go
auth.SetSessionIDCookie(w, r, sessionID)
```

See [Credentials sign-in](./credentials-login.md) for a complete handler.

## Lower-level helpers

| Function | Use |
|---|---|
| `auth.ExtractToken(raw)` | Validate a refresh token and get `*goauth.RefreshTokenClaims` |
| `auth.RefreshAccessToken(claims, session)` | Sign a new access token for a validated session |
| `auth.SignTokenPair(opts, sessionID)` | Sign a pair for an existing session id |
| `auth.GetTokenFromHeader(h)` | Strip `Bearer ` / `Token ` from a header value |
| `goauth.ParseCustomDuration(s, def)` | Parse `"15m"`, `"7d"`, `"1y"` |

```go
claims, err := auth.ExtractToken(refreshToken)
if err != nil {
	return err
}
session, err := auth.GetSession(ctx, claims.SessionID)
if err != nil {
	return err
}
access, err := auth.RefreshAccessToken(claims, session)
```
