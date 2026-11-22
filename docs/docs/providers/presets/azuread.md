---
title: Azure Active Directory
description: Sign in with Azure Active Directory using the goauth `azuread` provider preset.
---

# Azure Active Directory

Use the [`providers/azuread`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/azuread) preset to add Azure Active Directory sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/azuread"
)

Providers: []goauth.Provider{
	azuread.New(azuread.Options{
		ClientID:     os.Getenv("AZUREAD_CLIENT_ID"),
		ClientSecret: os.Getenv("AZUREAD_CLIENT_SECRET"),
		TenantID:     os.Getenv("AZUREAD_TENANT_ID"), // optional
	}),
},
```

Detailed Azure portal setup: [Azure AD / Entra ID](../azure-ad.md).

## Endpoints

```text
GET|POST /api/authorization/provider/azuread-v2
GET|POST /api/authorization/provider/azuread-v2/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/azuread-v2/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `azuread-v2` |
| Display name | Azure Active Directory |
| Type | `oidc` |
| Default scopes | `openid`, `profile`, `email`, `User.Read`, `Files.Read`, `Files.ReadWrite`, `Mail.Read`, `Mail.Send` |
| Checks | PKCE, State, Nonce |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `TenantID` | no | Directory / tenant id |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `azuread-v2` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`azuread.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := azuread.New(azuread.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
