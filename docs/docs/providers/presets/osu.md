---
title: osu!
description: Sign in with osu! using the goauth `osu` provider preset.
---

# osu!

Use the [`providers/osu`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/osu) preset to add osu! sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/osu"
)

Providers: []goauth.Provider{
	osu.New(osu.Options{
		ClientID:     os.Getenv("OSU_CLIENT_ID"),
		ClientSecret: os.Getenv("OSU_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/osu
GET|POST /api/authorization/provider/osu/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/osu/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `osu` |
| Display name | osu! |
| Type | `oauth` |
| Default scopes | `identify` |
| Checks | State |
| Authorization URL | `https://osu.ppy.sh/oauth/authorize` |
| Token URL | `https://osu.ppy.sh/oauth/token` |
| Userinfo URL | `https://osu.ppy.sh/api/v2/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `osu` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`osu.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := osu.New(osu.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
