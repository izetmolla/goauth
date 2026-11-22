---
title: Spotify
description: Sign in with Spotify using the goauth `spotify` provider preset.
---

# Spotify

Use the [`providers/spotify`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/spotify) preset to add Spotify sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/spotify"
)

Providers: []goauth.Provider{
	spotify.New(spotify.Options{
		ClientID:     os.Getenv("SPOTIFY_CLIENT_ID"),
		ClientSecret: os.Getenv("SPOTIFY_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/spotify
GET|POST /api/authorization/provider/spotify/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/spotify/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `spotify` |
| Display name | Spotify |
| Type | `oauth` |
| Default scopes | `user-read-email` |
| Checks | State |
| Authorization URL | `https://accounts.spotify.com/authorize` |
| Token URL | `https://accounts.spotify.com/api/token` |
| Userinfo URL | `https://api.spotify.com/v1/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `spotify` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`spotify.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := spotify.New(spotify.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
