---
title: Descope
description: Sign in with Descope using the goauth `descope` provider preset.
---

# Descope

Use the [`providers/descope`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/descope) preset to add Descope sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/descope"
)

Providers: []goauth.Provider{
	descope.New(descope.Options{
		ClientID:     os.Getenv("DESCOPE_CLIENT_ID"),
		ClientSecret: os.Getenv("DESCOPE_CLIENT_SECRET"),
		Issuer:       os.Getenv("DESCOPE_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/descope
GET|POST /api/authorization/provider/descope/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/descope/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `descope` |
| Display name | Descope |
| Type | `oidc` |
| Default scopes | `openid`, `profile`, `email` |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `descope` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`descope.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := descope.New(descope.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
