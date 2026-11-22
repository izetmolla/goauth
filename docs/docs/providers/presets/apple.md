---
title: Apple
description: Sign in with Apple using the goauth `apple` provider preset.
---

# Apple

Use the [`providers/apple`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/apple) preset to add Apple sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/apple"
)

Providers: []goauth.Provider{
	apple.New(apple.Options{
		ClientID:     os.Getenv("APPLE_CLIENT_ID"),
		ClientSecret: os.Getenv("APPLE_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/apple
GET|POST /api/authorization/provider/apple/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/apple/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `apple` |
| Display name | Apple |
| Type | `oidc` |
| Default scopes | `name`, `email` |
| Checks | PKCE, State, Nonce |
| Issuer | `https://appleid.apple.com` |
| Authorization URL | `https://appleid.apple.com/auth/authorize` |
| Token URL | `https://appleid.apple.com/auth/token` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `apple` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`apple.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := apple.New(apple.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
