---
title: Netlify
description: Sign in with Netlify using the goauth `netlify` provider preset.
---

# Netlify

Use the [`providers/netlify`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/netlify) preset to add Netlify sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/netlify"
)

Providers: []goauth.Provider{
	netlify.New(netlify.Options{
		ClientID:     os.Getenv("NETLIFY_CLIENT_ID"),
		ClientSecret: os.Getenv("NETLIFY_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/netlify
GET|POST /api/authorization/provider/netlify/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/netlify/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `netlify` |
| Display name | Netlify |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://app.netlify.com/authorize` |
| Token URL | `https://api.netlify.com/oauth/token` |
| Userinfo URL | `https://api.netlify.com/api/v1/user` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `netlify` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`netlify.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := netlify.New(netlify.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
