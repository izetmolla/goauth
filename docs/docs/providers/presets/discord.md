---
title: Discord
description: Sign in with Discord using the goauth `discord` provider preset.
---

# Discord

Use the [`providers/discord`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/discord) preset to add Discord sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/discord"
)

Providers: []goauth.Provider{
	discord.New(discord.Options{
		ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/discord
GET|POST /api/authorization/provider/discord/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/discord/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `discord` |
| Display name | Discord |
| Type | `oauth` |
| Default scopes | `identify`, `email` |
| Checks | State |
| Authorization URL | `https://discord.com/api/oauth2/authorize` |
| Token URL | `https://discord.com/api/oauth2/token` |
| Userinfo URL | `https://discord.com/api/users/@me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `discord` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`discord.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := discord.New(discord.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
