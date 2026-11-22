---
title: Battle.net
description: Sign in with Battle.net using the goauth `battlenet` provider preset.
---

# Battle.net

Use the [`providers/battlenet`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/battlenet) preset to add Battle.net sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/battlenet"
)

Providers: []goauth.Provider{
	battlenet.New(battlenet.Options{
		ClientID:     os.Getenv("BATTLENET_CLIENT_ID"),
		ClientSecret: os.Getenv("BATTLENET_CLIENT_SECRET"),
		Issuer:       os.Getenv("BATTLENET_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/battlenet
GET|POST /api/authorization/provider/battlenet/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/battlenet/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `battlenet` |
| Display name | Battle.net |
| Type | `oidc` |
| Default scopes | `openid` |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `battlenet` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`battlenet.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := battlenet.New(battlenet.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
