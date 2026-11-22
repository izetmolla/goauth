---
title: Faceit
description: Sign in with Faceit using the goauth `faceit` provider preset.
---

# Faceit

Use the [`providers/faceit`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/faceit) preset to add Faceit sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/faceit"
)

Providers: []goauth.Provider{
	faceit.New(faceit.Options{
		ClientID:     os.Getenv("FACEIT_CLIENT_ID"),
		ClientSecret: os.Getenv("FACEIT_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/faceit
GET|POST /api/authorization/provider/faceit/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/faceit/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `faceit` |
| Display name | Faceit |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://accounts.faceit.com/accounts?redirect_popup=true` |
| Token URL | `https://api.faceit.com/auth/v1/oauth/token` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `faceit` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`faceit.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := faceit.New(faceit.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
