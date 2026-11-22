---
title: Azure DevOps
description: Sign in with Azure DevOps using the goauth `azuredevops` provider preset.
---

# Azure DevOps

Use the [`providers/azuredevops`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/azuredevops) preset to add Azure DevOps sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/azuredevops"
)

Providers: []goauth.Provider{
	azuredevops.New(azuredevops.Options{
		ClientID:     os.Getenv("AZUREDEVOPS_CLIENT_ID"),
		ClientSecret: os.Getenv("AZUREDEVOPS_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/azure-devops
GET|POST /api/authorization/provider/azure-devops/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/azure-devops/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `azure-devops` |
| Display name | Azure DevOps |
| Type | `oauth` |
| Default scopes | `vso.profile` |
| Checks | State |
| Authorization URL | `https://app.vssps.visualstudio.com/oauth2/authorize` |
| Token URL | `https://app.vssps.visualstudio.com/oauth2/token` |
| Userinfo URL | `https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=6.0` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `azure-devops` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`azuredevops.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := azuredevops.New(azuredevops.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
