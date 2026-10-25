---
title: Protecting API routes
description: Use UseAPIAuthorization to require a Bearer JWT, read the caller's identity, and exclude public paths.
---

# Protecting API routes

`auth.UseAPIAuthorization` is a standard `func(http.Handler) http.Handler` middleware that requires a valid **access token**.

## Basic usage

```go
me := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	data, err := auth.GetAuthDataAPI(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"user_id": data.UserID,
		"roles":   data.Roles,
	})
})

mux.Handle("GET /api/me", auth.UseAPIAuthorization()(me))
```

```bash
curl -H "Authorization: Bearer eyJhbGciOi..." https://app.example.com/api/me
```

## Where the token is read from

1. The `Authorization` header with the `Bearer` scheme (case-insensitive).
2. Otherwise, the `access_token` query parameter, for clients that cannot set headers (for example `EventSource` or WebSocket upgrades):

   ```js
   new EventSource(`/api/events?access_token=${encodeURIComponent(token)}`);
   ```

:::tip
Query-string tokens can end up in proxy and access logs. Prefer the header, and keep access tokens short-lived.
:::

## What the middleware checks

1. The token is present and correctly signed with `JWTSecret` using HMAC (`HS256`/`HS384`/`HS512`). Tokens with any other `alg` are rejected.
2. It has not expired.
3. It is an **access** token. Refresh tokens are rejected.
4. If you passed `WithRoles`, the caller holds one of the roles.

Validation is stateless: no database or Redis lookup happens.

On failure:

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json; charset=utf-8

{"error":"token has invalid claims: token is expired","code":"UNAUTHORIZED"}
```

## Reading the caller

Inside a protected handler:

```go
data, err := auth.GetAuthDataAPI(r) // goauth.AuthData{SessionID, UserID, Roles}

claims, err := auth.GetClaims(r) // jwt.MapClaims: user_id, roles, content, exp, iat, token_type
roles, err := auth.GetRoles(r)   // []string{"admin:rw", "hr:r"}

token := goauth.JWTFromContext(r.Context()) // *jwt.Token, or nil
```

`AuthData.SessionID` is empty for access tokens: they intentionally carry no session id. Use `auth.User(r, ctx, true)` for the same data as a pointer.

The `content` claim is reserved for custom data and is currently always an empty object. There is no exported option to fill it yet, so load extra user data from your database using `data.UserID`.

## Role gates

```go
admin := auth.UseAPIAuthorization(auth.WithRoles([]string{"admin"}))
mux.Handle("DELETE /api/users/{id}", admin(deleteUser))
```

The caller needs **at least one** of the listed roles, otherwise:

```json
{"error":"insufficient permissions: admin","code":"INSUFFICIENT_PERMISSIONS"}
```

with status `403`. See [Roles and permissions](./roles-and-permissions.md) for read/write grants.

## Protecting a whole subtree

Wrap a sub-router once and exclude the public parts:

```go
api := http.NewServeMux()
api.HandleFunc("GET /api/health", health)
api.HandleFunc("GET /api/public/posts", listPosts)
api.HandleFunc("GET /api/me", me)
api.HandleFunc("POST /api/posts", createPost)

protected := auth.UseAPIAuthorization(
	auth.WithExcludedPaths([]string{"/api/health", "/api/public"}),
)
mux.Handle("/api/", protected(api))
```

:::warning[Prefix matching]
Excluded paths match by **prefix**: `/api/public` also excludes `/api/publications`. End a prefix with `/` (`"/api/public/"`) when you want only that directory.
:::

## Combining middlewares

Middlewares are plain functions, so they compose:

```go
func chain(h http.Handler, mws ...goauth.Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

mux.Handle("POST /api/reports", chain(createReport,
	logging,
	auth.UseAPIAuthorization(auth.WithRoles([]string{"finance", "admin"})),
))
```

## CORS for browser clients

If your SPA runs on another origin, the browser sends a preflight request without the `Authorization` header. Answer `OPTIONS` **before** the auth middleware:

```go
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://spa.example.com")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, cft")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

http.ListenAndServe(":3000", cors(mux))
```

The `cft` header is needed for [token refresh](./tokens-and-refresh.md).
