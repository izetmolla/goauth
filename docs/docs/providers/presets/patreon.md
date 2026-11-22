---
title: Patreon
description: Sign in with Patreon using the goauth `patreon` provider preset.
---

# Patreon

Use the [`providers/patreon`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/patreon) preset to add Patreon sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/patreon"
)

Providers: []goauth.Provider{
	patreon.New(patreon.Options{
		ClientID:     os.Getenv("PATREON_CLIENT_ID"),
		ClientSecret: os.Getenv("PATREON_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/patreon
GET|POST /api/authorization/provider/patreon/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/patreon/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `patreon` |
| Display name | Patreon |
| Type | `oauth` |
| Default scopes | `identity`, `identity[email]` |
| Checks | State |
| Authorization URL | `https://www.patreon.com/oauth2/authorize` |
| Token URL | `https://www.patreon.com/api/oauth2/token` |
| Userinfo URL | `https://www.patreon.com/api/oauth2/v2/identity?fields%5Buser%5D=email,first_name,image_url,last_name,full_name` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `patreon` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`patreon.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := patreon.New(patreon.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
