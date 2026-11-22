---
title: Threads
description: Sign in with Threads using the goauth `threads` provider preset.
---

# Threads

Use the [`providers/threads`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/threads) preset to add Threads sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/threads"
)

Providers: []goauth.Provider{
	threads.New(threads.Options{
		ClientID:     os.Getenv("THREADS_CLIENT_ID"),
		ClientSecret: os.Getenv("THREADS_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/threads
GET|POST /api/authorization/provider/threads/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/threads/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `threads` |
| Display name | Threads |
| Type | `oauth` |
| Default scopes | `threads_basic` |
| Checks | State |
| Authorization URL | `https://threads.net/oauth/authorize` |
| Token URL | `https://graph.threads.net/oauth/access_token` |
| Userinfo URL | `https://graph.threads.net/v1.0/me?fields=id,username,threads_profile_picture_url` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `threads` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`threads.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := threads.New(threads.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
