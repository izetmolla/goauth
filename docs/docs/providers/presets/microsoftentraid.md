---
title: Microsoft Entra ID
description: Sign in with Microsoft Entra ID using the goauth `microsoftentraid` provider preset.
---

# Microsoft Entra ID

Use the [`providers/microsoftentraid`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/microsoftentraid) preset to add Microsoft Entra ID sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/microsoftentraid"
)

Providers: []goauth.Provider{
	microsoftentraid.New(microsoftentraid.Options{
		ClientID:     os.Getenv("MICROSOFTENTRAID_CLIENT_ID"),
		ClientSecret: os.Getenv("MICROSOFTENTRAID_CLIENT_SECRET"),
		Issuer:       os.Getenv("MICROSOFTENTRAID_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/microsoft-entra-id
GET|POST /api/authorization/provider/microsoft-entra-id/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/microsoft-entra-id/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `microsoft-entra-id` |
| Display name | Microsoft Entra ID |
| Type | `oidc` |
| Default scopes | `openid`, `profile`, `email`, `User.Read` |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `microsoft-entra-id` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`microsoftentraid.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := microsoftentraid.New(microsoftentraid.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
