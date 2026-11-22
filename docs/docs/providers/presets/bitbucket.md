---
title: Bitbucket
description: Sign in with Bitbucket using the goauth `bitbucket` provider preset.
---

# Bitbucket

Use the [`providers/bitbucket`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/bitbucket) preset to add Bitbucket sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/bitbucket"
)

Providers: []goauth.Provider{
	bitbucket.New(bitbucket.Options{
		ClientID:     os.Getenv("BITBUCKET_CLIENT_ID"),
		ClientSecret: os.Getenv("BITBUCKET_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/bitbucket
GET|POST /api/authorization/provider/bitbucket/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/bitbucket/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `bitbucket` |
| Display name | Bitbucket |
| Type | `oauth` |
| Default scopes | `account` |
| Checks | State |
| Authorization URL | `https://bitbucket.org/site/oauth2/authorize` |
| Token URL | `https://bitbucket.org/site/oauth2/access_token` |
| Userinfo URL | `https://api.bitbucket.org/2.0/user` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `bitbucket` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`bitbucket.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := bitbucket.New(bitbucket.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
