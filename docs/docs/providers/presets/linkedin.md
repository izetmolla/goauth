---
title: LinkedIn
description: Sign in with LinkedIn using the goauth `linkedin` provider preset.
---

# LinkedIn

Use the [`providers/linkedin`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/linkedin) preset to add LinkedIn sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/linkedin"
)

Providers: []goauth.Provider{
	linkedin.New(linkedin.Options{
		ClientID:     os.Getenv("LINKEDIN_CLIENT_ID"),
		ClientSecret: os.Getenv("LINKEDIN_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/linkedin
GET|POST /api/authorization/provider/linkedin/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/linkedin/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `linkedin` |
| Display name | LinkedIn |
| Type | `oidc` |
| Default scopes | `openid`, `profile`, `email` |
| Checks | State |
| Issuer | `https://www.linkedin.com/oauth` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `linkedin` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`linkedin.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := linkedin.New(linkedin.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
