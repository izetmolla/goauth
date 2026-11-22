---
title: Zoom
description: Sign in with Zoom using the goauth `zoom` provider preset.
---

# Zoom

Use the [`providers/zoom`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/zoom) preset to add Zoom sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/zoom"
)

Providers: []goauth.Provider{
	zoom.New(zoom.Options{
		ClientID:     os.Getenv("ZOOM_CLIENT_ID"),
		ClientSecret: os.Getenv("ZOOM_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/zoom
GET|POST /api/authorization/provider/zoom/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/zoom/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `zoom` |
| Display name | Zoom |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://zoom.us/oauth/authorize` |
| Token URL | `https://zoom.us/oauth/token` |
| Userinfo URL | `https://api.zoom.us/v2/users/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `zoom` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`zoom.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := zoom.New(zoom.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
