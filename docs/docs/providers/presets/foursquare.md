---
title: Foursquare
description: Sign in with Foursquare using the goauth `foursquare` provider preset.
---

# Foursquare

Use the [`providers/foursquare`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/foursquare) preset to add Foursquare sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/foursquare"
)

Providers: []goauth.Provider{
	foursquare.New(foursquare.Options{
		ClientID:     os.Getenv("FOURSQUARE_CLIENT_ID"),
		ClientSecret: os.Getenv("FOURSQUARE_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/foursquare
GET|POST /api/authorization/provider/foursquare/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/foursquare/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `foursquare` |
| Display name | Foursquare |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://foursquare.com/oauth2/authenticate` |
| Token URL | `https://foursquare.com/oauth2/access_token` |
| Userinfo URL | `https://api.foursquare.com/v2/users/self` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `foursquare` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`foursquare.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := foursquare.New(foursquare.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
