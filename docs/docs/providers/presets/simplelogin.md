---
title: SimpleLogin
description: Sign in with SimpleLogin using the goauth `simplelogin` provider preset.
---

# SimpleLogin

Use the [`providers/simplelogin`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/simplelogin) preset to add SimpleLogin sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/simplelogin"
)

Providers: []goauth.Provider{
	simplelogin.New(simplelogin.Options{
		ClientID:     os.Getenv("SIMPLELOGIN_CLIENT_ID"),
		ClientSecret: os.Getenv("SIMPLELOGIN_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/simplelogin
GET|POST /api/authorization/provider/simplelogin/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/simplelogin/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `simplelogin` |
| Display name | SimpleLogin |
| Type | `oidc` |
| Default scopes | `openid`, `profile`, `email` |
| Checks | PKCE, State, Nonce |
| Issuer | `https://app.simplelogin.io` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `simplelogin` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`simplelogin.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := simplelogin.New(simplelogin.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
