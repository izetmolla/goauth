---
title: Reddit
description: Sign in with Reddit using the goauth `reddit` provider preset.
---

# Reddit

Use the [`providers/reddit`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/reddit) preset to add Reddit sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/reddit"
)

Providers: []goauth.Provider{
	reddit.New(reddit.Options{
		ClientID:     os.Getenv("REDDIT_CLIENT_ID"),
		ClientSecret: os.Getenv("REDDIT_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/reddit
GET|POST /api/authorization/provider/reddit/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/reddit/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `reddit` |
| Display name | Reddit |
| Type | `oauth` |
| Default scopes | `identity` |
| Checks | State |
| Authorization URL | `https://www.reddit.com/api/v1/authorize` |
| Token URL | `https://www.reddit.com/api/v1/access_token` |
| Userinfo URL | `https://oauth.reddit.com/api/v1/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `reddit` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`reddit.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := reddit.New(reddit.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
