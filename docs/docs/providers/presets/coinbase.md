---
title: Coinbase
description: Sign in with Coinbase using the goauth `coinbase` provider preset.
---

# Coinbase

Use the [`providers/coinbase`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/coinbase) preset to add Coinbase sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/coinbase"
)

Providers: []goauth.Provider{
	coinbase.New(coinbase.Options{
		ClientID:     os.Getenv("COINBASE_CLIENT_ID"),
		ClientSecret: os.Getenv("COINBASE_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/coinbase
GET|POST /api/authorization/provider/coinbase/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/coinbase/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `coinbase` |
| Display name | Coinbase |
| Type | `oauth` |
| Default scopes | `wallet:user:email`, `wallet:user:read` |
| Checks | State |
| Authorization URL | `https://login.coinbase.com/oauth2/auth` |
| Token URL | `https://login.coinbase.com/oauth2/token` |
| Userinfo URL | `https://api.coinbase.com/v2/user` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `coinbase` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`coinbase.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := coinbase.New(coinbase.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
