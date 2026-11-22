---
title: Figma
description: Sign in with Figma using the goauth `figma` provider preset.
---

# Figma

Use the [`providers/figma`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/figma) preset to add Figma sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/figma"
)

Providers: []goauth.Provider{
	figma.New(figma.Options{
		ClientID:     os.Getenv("FIGMA_CLIENT_ID"),
		ClientSecret: os.Getenv("FIGMA_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/figma
GET|POST /api/authorization/provider/figma/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/figma/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `figma` |
| Display name | Figma |
| Type | `oauth` |
| Default scopes | `file_read` |
| Checks | State |
| Authorization URL | `https://www.figma.com/oauth` |
| Token URL | `https://www.figma.com/api/oauth/token` |
| Userinfo URL | `https://api.figma.com/v1/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `figma` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`figma.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := figma.New(figma.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
