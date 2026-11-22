---
title: Freshbooks
description: Sign in with Freshbooks using the goauth `freshbooks` provider preset.
---

# Freshbooks

Use the [`providers/freshbooks`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/freshbooks) preset to add Freshbooks sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/freshbooks"
)

Providers: []goauth.Provider{
	freshbooks.New(freshbooks.Options{
		ClientID:     os.Getenv("FRESHBOOKS_CLIENT_ID"),
		ClientSecret: os.Getenv("FRESHBOOKS_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/freshbooks
GET|POST /api/authorization/provider/freshbooks/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/freshbooks/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `freshbooks` |
| Display name | Freshbooks |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://auth.freshbooks.com/oauth/authorize` |
| Token URL | `https://api.freshbooks.com/auth/oauth/token` |
| Userinfo URL | `https://api.freshbooks.com/auth/api/v1/users/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `freshbooks` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`freshbooks.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := freshbooks.New(freshbooks.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
