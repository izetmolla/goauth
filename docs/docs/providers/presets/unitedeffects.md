---
title: United Effects
description: Sign in with United Effects using the goauth `unitedeffects` provider preset.
---

# United Effects

Use the [`providers/unitedeffects`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/unitedeffects) preset to add United Effects sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/unitedeffects"
)

Providers: []goauth.Provider{
	unitedeffects.New(unitedeffects.Options{
		ClientID:     os.Getenv("UNITEDEFFECTS_CLIENT_ID"),
		ClientSecret: os.Getenv("UNITEDEFFECTS_CLIENT_SECRET"),
		Issuer:       os.Getenv("UNITEDEFFECTS_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/united-effects
GET|POST /api/authorization/provider/united-effects/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/united-effects/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `united-effects` |
| Display name | United Effects |
| Type | `oidc` |
| Default scopes | `openid`, `email`, `profile` |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `united-effects` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`unitedeffects.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := unitedeffects.New(unitedeffects.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
