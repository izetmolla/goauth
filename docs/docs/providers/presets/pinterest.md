---
title: Pinterest
description: Sign in with Pinterest using the goauth `pinterest` provider preset.
---

# Pinterest

Use the [`providers/pinterest`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/pinterest) preset to add Pinterest sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/pinterest"
)

Providers: []goauth.Provider{
	pinterest.New(pinterest.Options{
		ClientID:     os.Getenv("PINTEREST_CLIENT_ID"),
		ClientSecret: os.Getenv("PINTEREST_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/pinterest
GET|POST /api/authorization/provider/pinterest/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/pinterest/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `pinterest` |
| Display name | Pinterest |
| Type | `oauth` |
| Default scopes | `user_accounts:read` |
| Checks | State |
| Authorization URL | `https://www.pinterest.com/oauth` |
| Token URL | `https://api.pinterest.com/v5/oauth/token` |
| Userinfo URL | `https://api.pinterest.com/v5/user_account` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `pinterest` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`pinterest.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := pinterest.New(pinterest.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
