---
title: Facebook
description: Sign in with Facebook using the goauth `facebook` provider preset.
---

# Facebook

Use the [`providers/facebook`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/facebook) preset to add Facebook sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/facebook"
)

Providers: []goauth.Provider{
	facebook.New(facebook.Options{
		ClientID:     os.Getenv("FACEBOOK_CLIENT_ID"),
		ClientSecret: os.Getenv("FACEBOOK_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/facebook
GET|POST /api/authorization/provider/facebook/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/facebook/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `facebook` |
| Display name | Facebook |
| Type | `oauth` |
| Default scopes | `email` |
| Checks | State |
| Authorization URL | `https://www.facebook.com/v19.0/dialog/oauth` |
| Token URL | `https://graph.facebook.com/oauth/access_token` |
| Userinfo URL | `https://graph.facebook.com/me?fields=id,name,email,picture` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `facebook` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`facebook.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := facebook.New(facebook.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
