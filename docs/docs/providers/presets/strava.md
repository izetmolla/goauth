---
title: Strava
description: Sign in with Strava using the goauth `strava` provider preset.
---

# Strava

Use the [`providers/strava`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/strava) preset to add Strava sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/strava"
)

Providers: []goauth.Provider{
	strava.New(strava.Options{
		ClientID:     os.Getenv("STRAVA_CLIENT_ID"),
		ClientSecret: os.Getenv("STRAVA_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/strava
GET|POST /api/authorization/provider/strava/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/strava/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `strava` |
| Display name | Strava |
| Type | `oauth` |
| Default scopes | `read` |
| Checks | State |
| Authorization URL | `https://www.strava.com/api/v3/oauth/authorize` |
| Token URL | `https://www.strava.com/api/v3/oauth/token` |
| Userinfo URL | `https://www.strava.com/api/v3/athlete` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `strava` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`strava.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := strava.New(strava.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
