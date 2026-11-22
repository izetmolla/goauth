---
title: Dribbble
description: Sign in with Dribbble using the goauth `dribbble` provider preset.
---

# Dribbble

Use the [`providers/dribbble`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/dribbble) preset to add Dribbble sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/dribbble"
)

Providers: []goauth.Provider{
	dribbble.New(dribbble.Options{
		ClientID:     os.Getenv("DRIBBBLE_CLIENT_ID"),
		ClientSecret: os.Getenv("DRIBBBLE_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/dribbble
GET|POST /api/authorization/provider/dribbble/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/dribbble/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `dribbble` |
| Display name | Dribbble |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://dribbble.com/oauth/authorize` |
| Token URL | `https://dribbble.com/oauth/token` |
| Userinfo URL | `https://api.dribbble.com/v2/user` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `dribbble` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`dribbble.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := dribbble.New(dribbble.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
