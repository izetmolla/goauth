---
title: Webex
description: Sign in with Webex using the goauth `webex` provider preset.
---

# Webex

Use the [`providers/webex`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/webex) preset to add Webex sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/webex"
)

Providers: []goauth.Provider{
	webex.New(webex.Options{
		ClientID:     os.Getenv("WEBEX_CLIENT_ID"),
		ClientSecret: os.Getenv("WEBEX_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/webex
GET|POST /api/authorization/provider/webex/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/webex/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `webex` |
| Display name | Webex |
| Type | `oauth` |
| Default scopes | `spark:kms`, `spark:people_read` |
| Checks | State |
| Authorization URL | `https://webexapis.com/v1/authorize` |
| Token URL | `https://webexapis.com/v1/access_token` |
| Userinfo URL | `https://webexapis.com/v1/people/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `webex` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`webex.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := webex.New(webex.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
