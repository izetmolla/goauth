---
title: Asgardeo
description: Sign in with Asgardeo using the goauth `asgardeo` provider preset.
---

# Asgardeo

Use the [`providers/asgardeo`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/asgardeo) preset to add Asgardeo sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/asgardeo"
)

Providers: []goauth.Provider{
	asgardeo.New(asgardeo.Options{
		ClientID:     os.Getenv("ASGARDEO_CLIENT_ID"),
		ClientSecret: os.Getenv("ASGARDEO_CLIENT_SECRET"),
		Issuer:       os.Getenv("ASGARDEO_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/asgardeo
GET|POST /api/authorization/provider/asgardeo/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/asgardeo/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `asgardeo` |
| Display name | Asgardeo |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `asgardeo` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`asgardeo.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := asgardeo.New(asgardeo.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
