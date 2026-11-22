---
title: 42 School
description: Sign in with 42 School using the goauth `school42` provider preset.
---

# 42 School

Use the [`providers/school42`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/school42) preset to add 42 School sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/school42"
)

Providers: []goauth.Provider{
	school42.New(school42.Options{
		ClientID:     os.Getenv("SCHOOL42_CLIENT_ID"),
		ClientSecret: os.Getenv("SCHOOL42_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/42-school
GET|POST /api/authorization/provider/42-school/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/42-school/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `42-school` |
| Display name | 42 School |
| Type | `oauth` |
| Default scopes | `public` |
| Checks | State |
| Authorization URL | `https://api.intra.42.fr/oauth/authorize` |
| Token URL | `https://api.intra.42.fr/oauth/token` |
| Userinfo URL | `https://api.intra.42.fr/v2/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `42-school` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`school42.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := school42.New(school42.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
