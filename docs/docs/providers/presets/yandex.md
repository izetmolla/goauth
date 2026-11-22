---
title: Yandex
description: Sign in with Yandex using the goauth `yandex` provider preset.
---

# Yandex

Use the [`providers/yandex`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/yandex) preset to add Yandex sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/yandex"
)

Providers: []goauth.Provider{
	yandex.New(yandex.Options{
		ClientID:     os.Getenv("YANDEX_CLIENT_ID"),
		ClientSecret: os.Getenv("YANDEX_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/yandex
GET|POST /api/authorization/provider/yandex/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/yandex/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `yandex` |
| Display name | Yandex |
| Type | `oauth` |
| Default scopes | `login:info`, `login:email`, `login:avatar` |
| Checks | State |
| Authorization URL | `https://oauth.yandex.ru/authorize` |
| Token URL | `https://oauth.yandex.ru/token` |
| Userinfo URL | `https://login.yandex.ru/info?format=json` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `yandex` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`yandex.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := yandex.New(yandex.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
