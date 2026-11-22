---
title: WorkOS
description: Sign in with WorkOS using the goauth `workos` provider preset.
---

# WorkOS

Use the [`providers/workos`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/workos) preset to add WorkOS sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/workos"
)

Providers: []goauth.Provider{
	workos.New(workos.Options{
		ClientID:     os.Getenv("WORKOS_CLIENT_ID"),
		ClientSecret: os.Getenv("WORKOS_CLIENT_SECRET"),
		Issuer:       os.Getenv("WORKOS_ISSUER"), // required OIDC issuer URL
		Connection: /* … */,
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/workos
GET|POST /api/authorization/provider/workos/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/workos/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `workos` |
| Display name | WorkOS |
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
| `Connection` | see package | `string` |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `workos` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`workos.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := workos.New(workos.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
