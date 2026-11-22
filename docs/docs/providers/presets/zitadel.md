---
title: ZITADEL
description: Sign in with ZITADEL using the goauth `zitadel` provider preset.
---

# ZITADEL

Use the [`providers/zitadel`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/zitadel) preset to add ZITADEL sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/zitadel"
)

Providers: []goauth.Provider{
	zitadel.New(zitadel.Options{
		ClientID:     os.Getenv("ZITADEL_CLIENT_ID"),
		ClientSecret: os.Getenv("ZITADEL_CLIENT_SECRET"),
		Issuer:       os.Getenv("ZITADEL_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/zitadel
GET|POST /api/authorization/provider/zitadel/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/zitadel/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `zitadel` |
| Display name | ZITADEL |
| Type | `oidc` |
| Default scopes | `openid`, `profile`, `email` |
| Checks | PKCE, State, Nonce |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `zitadel` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`zitadel.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := zitadel.New(zitadel.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
