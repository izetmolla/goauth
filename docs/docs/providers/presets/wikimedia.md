---
title: Wikimedia
description: Sign in with Wikimedia using the goauth `wikimedia` provider preset.
---

# Wikimedia

Use the [`providers/wikimedia`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/wikimedia) preset to add Wikimedia sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/wikimedia"
)

Providers: []goauth.Provider{
	wikimedia.New(wikimedia.Options{
		ClientID:     os.Getenv("WIKIMEDIA_CLIENT_ID"),
		ClientSecret: os.Getenv("WIKIMEDIA_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/wikimedia
GET|POST /api/authorization/provider/wikimedia/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/wikimedia/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `wikimedia` |
| Display name | Wikimedia |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://meta.wikimedia.org/w/rest.php/oauth2/authorize` |
| Token URL | `https://meta.wikimedia.org/w/rest.php/oauth2/access_token` |
| Userinfo URL | `https://meta.wikimedia.org/w/rest.php/oauth2/resource/profile` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `wikimedia` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`wikimedia.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := wikimedia.New(wikimedia.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
