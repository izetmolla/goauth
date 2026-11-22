---
title: WordPress.com
description: Sign in with WordPress.com using the goauth `wordpress` provider preset.
---

# WordPress.com

Use the [`providers/wordpress`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/wordpress) preset to add WordPress.com sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/wordpress"
)

Providers: []goauth.Provider{
	wordpress.New(wordpress.Options{
		ClientID:     os.Getenv("WORDPRESS_CLIENT_ID"),
		ClientSecret: os.Getenv("WORDPRESS_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/wordpress
GET|POST /api/authorization/provider/wordpress/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/wordpress/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `wordpress` |
| Display name | WordPress.com |
| Type | `oauth` |
| Default scopes | `auth` |
| Checks | State |
| Authorization URL | `https://public-api.wordpress.com/oauth2/authorize` |
| Token URL | `https://public-api.wordpress.com/oauth2/token` |
| Userinfo URL | `https://public-api.wordpress.com/rest/v1/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `wordpress` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`wordpress.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := wordpress.New(wordpress.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
