---
title: VK
description: Sign in with VK using the goauth `vk` provider preset.
---

# VK

Use the [`providers/vk`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/vk) preset to add VK sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/vk"
)

Providers: []goauth.Provider{
	vk.New(vk.Options{
		ClientID:     os.Getenv("VK_CLIENT_ID"),
		ClientSecret: os.Getenv("VK_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/vk
GET|POST /api/authorization/provider/vk/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/vk/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `vk` |
| Display name | VK |
| Type | `oauth` |
| Default scopes | `email` |
| Checks | State |
| Authorization URL | `https://oauth.vk.com/authorize` |
| Token URL | `https://oauth.vk.com/access_token` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `vk` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`vk.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := vk.New(vk.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
