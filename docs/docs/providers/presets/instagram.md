---
title: Instagram
description: Sign in with Instagram using the goauth `instagram` provider preset.
---

# Instagram

Use the [`providers/instagram`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/instagram) preset to add Instagram sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/instagram"
)

Providers: []goauth.Provider{
	instagram.New(instagram.Options{
		ClientID:     os.Getenv("INSTAGRAM_CLIENT_ID"),
		ClientSecret: os.Getenv("INSTAGRAM_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/instagram
GET|POST /api/authorization/provider/instagram/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/instagram/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `instagram` |
| Display name | Instagram |
| Type | `oauth` |
| Default scopes | `user_profile` |
| Checks | State |
| Authorization URL | `https://api.instagram.com/oauth/authorize` |
| Token URL | `https://api.instagram.com/oauth/access_token` |
| Userinfo URL | `https://graph.instagram.com/me?fields=id,username,account_type,name` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `instagram` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`instagram.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := instagram.New(instagram.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
