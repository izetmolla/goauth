---
title: Twitter
description: Sign in with Twitter using the goauth `twitter` provider preset.
---

# Twitter

Use the [`providers/twitter`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/twitter) preset to add Twitter sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/twitter"
)

Providers: []goauth.Provider{
	twitter.New(twitter.Options{
		ClientID:     os.Getenv("TWITTER_CLIENT_ID"),
		ClientSecret: os.Getenv("TWITTER_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/twitter
GET|POST /api/authorization/provider/twitter/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/twitter/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `twitter` |
| Display name | Twitter |
| Type | `oauth` |
| Default scopes | `users.read`, `tweet.read`, `offline.access` |
| Checks | PKCE, State |
| Authorization URL | `https://x.com/i/oauth2/authorize` |
| Token URL | `https://api.x.com/2/oauth2/token` |
| Userinfo URL | `https://api.x.com/2/users/me?user.fields=profile_image_url` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `twitter` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`twitter.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := twitter.New(twitter.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
