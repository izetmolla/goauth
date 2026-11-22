---
title: TikTok
description: Sign in with TikTok using the goauth `tiktok` provider preset.
---

# TikTok

Use the [`providers/tiktok`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/tiktok) preset to add TikTok sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/tiktok"
)

Providers: []goauth.Provider{
	tiktok.New(tiktok.Options{
		ClientID:     os.Getenv("TIKTOK_CLIENT_ID"),
		ClientSecret: os.Getenv("TIKTOK_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/tiktok
GET|POST /api/authorization/provider/tiktok/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/tiktok/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `tiktok` |
| Display name | TikTok |
| Type | `oauth` |
| Default scopes | `user.info.basic` |
| Checks | State |
| Authorization URL | `https://www.tiktok.com/v2/auth/authorize` |
| Token URL | `https://open.tiktokapis.com/v2/oauth/token/` |
| Userinfo URL | `https://open.tiktokapis.com/v2/user/info/?fields=open_id,avatar_url,display_name` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `tiktok` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`tiktok.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := tiktok.New(tiktok.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
