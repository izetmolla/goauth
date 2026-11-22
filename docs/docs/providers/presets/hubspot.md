---
title: HubSpot
description: Sign in with HubSpot using the goauth `hubspot` provider preset.
---

# HubSpot

Use the [`providers/hubspot`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/hubspot) preset to add HubSpot sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/hubspot"
)

Providers: []goauth.Provider{
	hubspot.New(hubspot.Options{
		ClientID:     os.Getenv("HUBSPOT_CLIENT_ID"),
		ClientSecret: os.Getenv("HUBSPOT_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/hubspot
GET|POST /api/authorization/provider/hubspot/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/hubspot/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `hubspot` |
| Display name | HubSpot |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://app.hubspot.com/oauth/authorize` |
| Token URL | `https://api.hubapi.com/oauth/v1/token` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `hubspot` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`hubspot.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := hubspot.New(hubspot.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
