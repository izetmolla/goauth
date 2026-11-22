---
title: Twitch
description: Sign in with Twitch using the goauth `twitch` provider preset.
---

# Twitch

Use the [`providers/twitch`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/twitch) preset to add Twitch sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/twitch"
)

Providers: []goauth.Provider{
	twitch.New(twitch.Options{
		ClientID:     os.Getenv("TWITCH_CLIENT_ID"),
		ClientSecret: os.Getenv("TWITCH_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/twitch
GET|POST /api/authorization/provider/twitch/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/twitch/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `twitch` |
| Display name | Twitch |
| Type | `oidc` |
| Default scopes | `openid`, `user:read:email` |
| Checks | PKCE, State, Nonce |
| Issuer | `https://id.twitch.tv/oauth2` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `twitch` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`twitch.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := twitch.New(twitch.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
