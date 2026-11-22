---
title: Mattermost
description: Sign in with Mattermost using the goauth `mattermost` provider preset.
---

# Mattermost

Use the [`providers/mattermost`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/mattermost) preset to add Mattermost sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/mattermost"
)

Providers: []goauth.Provider{
	mattermost.New(mattermost.Options{
		ClientID:     os.Getenv("MATTERMOST_CLIENT_ID"),
		ClientSecret: os.Getenv("MATTERMOST_CLIENT_SECRET"),
		Issuer:       os.Getenv("MATTERMOST_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/mattermost
GET|POST /api/authorization/provider/mattermost/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/mattermost/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `mattermost` |
| Display name | Mattermost |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Issuer | `https://your-issuer.example` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Issuer` | yes | OIDC issuer URL used for discovery |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `mattermost` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`mattermost.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := mattermost.New(mattermost.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
