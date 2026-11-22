---
title: ClickUp
description: Sign in with ClickUp using the goauth `clickup` provider preset.
---

# ClickUp

Use the [`providers/clickup`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/clickup) preset to add ClickUp sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/clickup"
)

Providers: []goauth.Provider{
	clickup.New(clickup.Options{
		ClientID:     os.Getenv("CLICKUP_CLIENT_ID"),
		ClientSecret: os.Getenv("CLICKUP_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/click-up
GET|POST /api/authorization/provider/click-up/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/click-up/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `click-up` |
| Display name | ClickUp |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://app.clickup.com/api` |
| Token URL | `https://api.clickup.com/api/v2/oauth/token` |
| Userinfo URL | `https://api.clickup.com/api/v2/user` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `click-up` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`clickup.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := clickup.New(clickup.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
