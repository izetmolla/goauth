---
title: Nextcloud
description: Sign in with Nextcloud using the goauth `nextcloud` provider preset.
---

# Nextcloud

Use the [`providers/nextcloud`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/nextcloud) preset to add Nextcloud sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/nextcloud"
)

Providers: []goauth.Provider{
	nextcloud.New(nextcloud.Options{
		ClientID:     os.Getenv("NEXTCLOUD_CLIENT_ID"),
		ClientSecret: os.Getenv("NEXTCLOUD_CLIENT_SECRET"),
		Issuer:       os.Getenv("NEXTCLOUD_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/nextcloud
GET|POST /api/authorization/provider/nextcloud/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/nextcloud/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `nextcloud` |
| Display name | Nextcloud |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `nextcloud` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`nextcloud.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := nextcloud.New(nextcloud.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
