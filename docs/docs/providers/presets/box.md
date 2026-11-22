---
title: Box
description: Sign in with Box using the goauth `box` provider preset.
---

# Box

Use the [`providers/box`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/box) preset to add Box sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/box"
)

Providers: []goauth.Provider{
	box.New(box.Options{
		ClientID:     os.Getenv("BOX_CLIENT_ID"),
		ClientSecret: os.Getenv("BOX_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/box
GET|POST /api/authorization/provider/box/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/box/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `box` |
| Display name | Box |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://account.box.com/api/oauth2/authorize` |
| Token URL | `https://api.box.com/oauth2/token` |
| Userinfo URL | `https://api.box.com/2.0/users/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `box` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`box.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := box.New(box.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
