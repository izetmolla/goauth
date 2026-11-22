---
title: GitHub
description: Sign in with GitHub using the goauth `github` provider preset.
---

# GitHub

Use the [`providers/github`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/github) preset to add GitHub sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/github"
)

Providers: []goauth.Provider{
	github.New(github.Options{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/github
GET|POST /api/authorization/provider/github/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/github/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `github` |
| Display name | GitHub |
| Type | `oauth` |
| Default scopes | `read:user`, `user:email` |
| Checks | State |
| Authorization URL | `https://github.com/login/oauth/authorize` |
| Token URL | `https://github.com/login/oauth/access_token` |
| Userinfo URL | `https://api.github.com/user` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `github` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`github.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := github.New(github.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
