---
title: Azure AD B2C
description: Sign in with Azure AD B2C using the goauth `azureadb2c` provider preset.
---

# Azure AD B2C

Use the [`providers/azureadb2c`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/azureadb2c) preset to add Azure AD B2C sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/azureadb2c"
)

Providers: []goauth.Provider{
	azureadb2c.New(azureadb2c.Options{
		ClientID:     os.Getenv("AZUREADB2C_CLIENT_ID"),
		ClientSecret: os.Getenv("AZUREADB2C_CLIENT_SECRET"),
		Issuer:       os.Getenv("AZUREADB2C_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/azure-ad-b2c
GET|POST /api/authorization/provider/azure-ad-b2c/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/azure-ad-b2c/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `azure-ad-b2c` |
| Display name | Azure AD B2C |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `azure-ad-b2c` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`azureadb2c.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := azureadb2c.New(azureadb2c.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
