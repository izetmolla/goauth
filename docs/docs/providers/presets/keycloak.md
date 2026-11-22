---
title: Keycloak
description: Sign in with Keycloak using the goauth `keycloak` provider preset.
---

# Keycloak

Use the [`providers/keycloak`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/keycloak) preset to add Keycloak sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/keycloak"
)

Providers: []goauth.Provider{
	keycloak.New(keycloak.Options{
		ClientID:     os.Getenv("KEYCLOAK_CLIENT_ID"),
		ClientSecret: os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		Issuer:       os.Getenv("KEYCLOAK_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/keycloak
GET|POST /api/authorization/provider/keycloak/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/keycloak/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `keycloak` |
| Display name | Keycloak |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `keycloak` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`keycloak.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := keycloak.New(keycloak.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
