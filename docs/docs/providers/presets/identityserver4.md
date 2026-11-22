---
title: IdentityServer4
description: Sign in with IdentityServer4 using the goauth `identityserver4` provider preset.
---

# IdentityServer4

Use the [`providers/identityserver4`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/identityserver4) preset to add IdentityServer4 sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/identityserver4"
)

Providers: []goauth.Provider{
	identityserver4.New(identityserver4.Options{
		ClientID:     os.Getenv("IDENTITYSERVER4_CLIENT_ID"),
		ClientSecret: os.Getenv("IDENTITYSERVER4_CLIENT_SECRET"),
		Issuer:       os.Getenv("IDENTITYSERVER4_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/identity-server4
GET|POST /api/authorization/provider/identity-server4/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/identity-server4/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `identity-server4` |
| Display name | IdentityServer4 |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `identity-server4` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`identityserver4.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := identityserver4.New(identityserver4.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
