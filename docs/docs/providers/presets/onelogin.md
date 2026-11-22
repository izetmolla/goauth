---
title: OneLogin
description: Sign in with OneLogin using the goauth `onelogin` provider preset.
---

# OneLogin

Use the [`providers/onelogin`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/onelogin) preset to add OneLogin sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/onelogin"
)

Providers: []goauth.Provider{
	onelogin.New(onelogin.Options{
		ClientID:     os.Getenv("ONELOGIN_CLIENT_ID"),
		ClientSecret: os.Getenv("ONELOGIN_CLIENT_SECRET"),
		Issuer:       os.Getenv("ONELOGIN_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/onelogin
GET|POST /api/authorization/provider/onelogin/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/onelogin/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `onelogin` |
| Display name | OneLogin |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `onelogin` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`onelogin.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := onelogin.New(onelogin.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
