---
title: Bungie
description: Sign in with Bungie using the goauth `bungie` provider preset.
---

# Bungie

Use the [`providers/bungie`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/bungie) preset to add Bungie sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/bungie"
)

Providers: []goauth.Provider{
	bungie.New(bungie.Options{
		ClientID:     os.Getenv("BUNGIE_CLIENT_ID"),
		ClientSecret: os.Getenv("BUNGIE_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/bungie
GET|POST /api/authorization/provider/bungie/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/bungie/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `bungie` |
| Display name | Bungie |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://www.bungie.net/en/OAuth/Authorize` |
| Token URL | `https://www.bungie.net/platform/app/oauth/token/` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `bungie` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`bungie.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := bungie.New(bungie.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
