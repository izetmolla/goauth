---
title: Duende IdentityServer6
description: Sign in with Duende IdentityServer6 using the goauth `duendeidentityserver6` provider preset.
---

# Duende IdentityServer6

Use the [`providers/duendeidentityserver6`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/duendeidentityserver6) preset to add Duende IdentityServer6 sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/duendeidentityserver6"
)

Providers: []goauth.Provider{
	duendeidentityserver6.New(duendeidentityserver6.Options{
		ClientID:     os.Getenv("DUENDEIDENTITYSERVER6_CLIENT_ID"),
		ClientSecret: os.Getenv("DUENDEIDENTITYSERVER6_CLIENT_SECRET"),
		Issuer:       os.Getenv("DUENDEIDENTITYSERVER6_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/duende-identity-server6
GET|POST /api/authorization/provider/duende-identity-server6/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/duende-identity-server6/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `duende-identity-server6` |
| Display name | Duende IdentityServer6 |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `duende-identity-server6` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`duendeidentityserver6.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := duendeidentityserver6.New(duendeidentityserver6.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
