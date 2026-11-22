---
title: Zoho
description: Sign in with Zoho using the goauth `zoho` provider preset.
---

# Zoho

Use the [`providers/zoho`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/zoho) preset to add Zoho sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/zoho"
)

Providers: []goauth.Provider{
	zoho.New(zoho.Options{
		ClientID:     os.Getenv("ZOHO_CLIENT_ID"),
		ClientSecret: os.Getenv("ZOHO_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/zoho
GET|POST /api/authorization/provider/zoho/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/zoho/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `zoho` |
| Display name | Zoho |
| Type | `oauth` |
| Default scopes | `AaaServer.profile.Read` |
| Checks | State |
| Authorization URL | `https://accounts.zoho.com/oauth/v2/auth` |
| Token URL | `https://accounts.zoho.com/oauth/v2/token` |
| Userinfo URL | `https://accounts.zoho.com/oauth/user/info` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `zoho` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`zoho.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := zoho.New(zoho.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
