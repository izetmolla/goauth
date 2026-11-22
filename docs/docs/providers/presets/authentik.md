---
title: Authentik
description: Sign in with Authentik using the goauth `authentik` provider preset.
---

# Authentik

Use the [`providers/authentik`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/authentik) preset to add Authentik sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/authentik"
)

Providers: []goauth.Provider{
	authentik.New(authentik.Options{
		ClientID:     os.Getenv("AUTHENTIK_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTHENTIK_CLIENT_SECRET"),
		Issuer:       os.Getenv("AUTHENTIK_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/authentik
GET|POST /api/authorization/provider/authentik/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/authentik/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `authentik` |
| Display name | Authentik |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `authentik` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`authentik.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := authentik.New(authentik.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
