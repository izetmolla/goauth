---
title: Osso
description: Sign in with Osso using the goauth `osso` provider preset.
---

# Osso

Use the [`providers/osso`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/osso) preset to add Osso sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/osso"
)

Providers: []goauth.Provider{
	osso.New(osso.Options{
		ClientID:     os.Getenv("OSSO_CLIENT_ID"),
		ClientSecret: os.Getenv("OSSO_CLIENT_SECRET"),
		Issuer:       os.Getenv("OSSO_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/osso
GET|POST /api/authorization/provider/osso/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/osso/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `osso` |
| Display name | Osso |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `osso` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`osso.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := osso.New(osso.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
