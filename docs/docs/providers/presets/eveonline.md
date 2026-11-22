---
title: EVE Online
description: Sign in with EVE Online using the goauth `eveonline` provider preset.
---

# EVE Online

Use the [`providers/eveonline`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/eveonline) preset to add EVE Online sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/eveonline"
)

Providers: []goauth.Provider{
	eveonline.New(eveonline.Options{
		ClientID:     os.Getenv("EVEONLINE_CLIENT_ID"),
		ClientSecret: os.Getenv("EVEONLINE_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/eveonline
GET|POST /api/authorization/provider/eveonline/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/eveonline/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `eveonline` |
| Display name | EVE Online |
| Type | `oauth` |
| Default scopes | `publicData` |
| Checks | State |
| Authorization URL | `https://login.eveonline.com/v2/oauth/authorize` |
| Token URL | `https://login.eveonline.com/v2/oauth/token` |
| Userinfo URL | `https://login.eveonline.com/oauth/verify` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `eveonline` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`eveonline.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := eveonline.New(eveonline.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
