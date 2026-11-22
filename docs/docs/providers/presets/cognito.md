---
title: Cognito
description: Sign in with Cognito using the goauth `cognito` provider preset.
---

# Cognito

Use the [`providers/cognito`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/cognito) preset to add Cognito sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/cognito"
)

Providers: []goauth.Provider{
	cognito.New(cognito.Options{
		ClientID:     os.Getenv("COGNITO_CLIENT_ID"),
		ClientSecret: os.Getenv("COGNITO_CLIENT_SECRET"),
		Issuer:       os.Getenv("COGNITO_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/cognito
GET|POST /api/authorization/provider/cognito/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/cognito/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `cognito` |
| Display name | Cognito |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `cognito` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`cognito.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := cognito.New(cognito.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
