---
title: LINE
description: Sign in with LINE using the goauth `line` provider preset.
---

# LINE

Use the [`providers/line`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/line) preset to add LINE sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/line"
)

Providers: []goauth.Provider{
	line.New(line.Options{
		ClientID:     os.Getenv("LINE_CLIENT_ID"),
		ClientSecret: os.Getenv("LINE_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/line
GET|POST /api/authorization/provider/line/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/line/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `line` |
| Display name | LINE |
| Type | `oauth` |
| Default scopes | `profile`, `openid`, `email` |
| Checks | State |
| Authorization URL | `https://access.line.me/oauth2/v2.1/authorize` |
| Token URL | `https://api.line.me/oauth2/v2.1/token` |
| Userinfo URL | `https://api.line.me/v2/profile` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `line` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`line.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := line.New(line.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
