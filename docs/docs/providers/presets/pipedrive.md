---
title: Pipedrive
description: Sign in with Pipedrive using the goauth `pipedrive` provider preset.
---

# Pipedrive

Use the [`providers/pipedrive`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/pipedrive) preset to add Pipedrive sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/pipedrive"
)

Providers: []goauth.Provider{
	pipedrive.New(pipedrive.Options{
		ClientID:     os.Getenv("PIPEDRIVE_CLIENT_ID"),
		ClientSecret: os.Getenv("PIPEDRIVE_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/pipedrive
GET|POST /api/authorization/provider/pipedrive/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/pipedrive/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `pipedrive` |
| Display name | Pipedrive |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://oauth.pipedrive.com/oauth/authorize` |
| Token URL | `https://oauth.pipedrive.com/oauth/token` |
| Userinfo URL | `https://api.pipedrive.com/v1/users/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `pipedrive` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`pipedrive.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := pipedrive.New(pipedrive.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
