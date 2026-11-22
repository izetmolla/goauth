---
title: Medium
description: Sign in with Medium using the goauth `medium` provider preset.
---

# Medium

Use the [`providers/medium`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/medium) preset to add Medium sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/medium"
)

Providers: []goauth.Provider{
	medium.New(medium.Options{
		ClientID:     os.Getenv("MEDIUM_CLIENT_ID"),
		ClientSecret: os.Getenv("MEDIUM_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/medium
GET|POST /api/authorization/provider/medium/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/medium/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `medium` |
| Display name | Medium |
| Type | `oauth` |
| Default scopes | `basicProfile` |
| Checks | State |
| Authorization URL | `https://medium.com/m/oauth/authorize` |
| Token URL | `https://api.medium.com/v1/tokens` |
| Userinfo URL | `https://api.medium.com/v1/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `medium` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`medium.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := medium.New(medium.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
