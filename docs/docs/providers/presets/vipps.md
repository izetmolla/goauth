---
title: Vipps MobilePay
description: Sign in with Vipps MobilePay using the goauth `vipps` provider preset.
---

# Vipps MobilePay

Use the [`providers/vipps`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/vipps) preset to add Vipps MobilePay sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/vipps"
)

Providers: []goauth.Provider{
	vipps.New(vipps.Options{
		ClientID:     os.Getenv("VIPPS_CLIENT_ID"),
		ClientSecret: os.Getenv("VIPPS_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/vipps
GET|POST /api/authorization/provider/vipps/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/vipps/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `vipps` |
| Display name | Vipps MobilePay |
| Type | `oidc` |
| Default scopes | `openid`, `name`, `email` |
| Checks | PKCE, State, Nonce |
| Issuer | `https://api.vipps.no/access-management-1.0/access/` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `vipps` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`vipps.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := vipps.New(vipps.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
