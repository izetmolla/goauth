---
title: Trakt
description: Sign in with Trakt using the goauth `trakt` provider preset.
---

# Trakt

Use the [`providers/trakt`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/trakt) preset to add Trakt sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/trakt"
)

Providers: []goauth.Provider{
	trakt.New(trakt.Options{
		ClientID:     os.Getenv("TRAKT_CLIENT_ID"),
		ClientSecret: os.Getenv("TRAKT_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/trakt
GET|POST /api/authorization/provider/trakt/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/trakt/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `trakt` |
| Display name | Trakt |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://trakt.tv/oauth/authorize` |
| Token URL | `https://api.trakt.tv/oauth/token` |
| Userinfo URL | `https://api.trakt.tv/users/me?extended=full` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `trakt` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`trakt.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := trakt.New(trakt.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
