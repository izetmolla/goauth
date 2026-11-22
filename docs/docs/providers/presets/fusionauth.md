---
title: FusionAuth
description: Sign in with FusionAuth using the goauth `fusionauth` provider preset.
---

# FusionAuth

Use the [`providers/fusionauth`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/fusionauth) preset to add FusionAuth sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/fusionauth"
)

Providers: []goauth.Provider{
	fusionauth.New(fusionauth.Options{
		ClientID:     os.Getenv("FUSIONAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("FUSIONAUTH_CLIENT_SECRET"),
		Issuer:       os.Getenv("FUSIONAUTH_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/fusionauth
GET|POST /api/authorization/provider/fusionauth/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/fusionauth/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `fusionauth` |
| Display name | FusionAuth |
| Type | `oidc` |
| Default scopes | `openid`, `email`, `profile`, `offline_access` |
| Checks | PKCE, State |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `fusionauth` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`fusionauth.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := fusionauth.New(fusionauth.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
