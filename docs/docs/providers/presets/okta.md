---
title: Okta
description: Sign in with Okta using the goauth `okta` provider preset.
---

# Okta

Use the [`providers/okta`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/okta) preset to add Okta sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/okta"
)

Providers: []goauth.Provider{
	okta.New(okta.Options{
		ClientID:     os.Getenv("OKTA_CLIENT_ID"),
		ClientSecret: os.Getenv("OKTA_CLIENT_SECRET"),
		Issuer:       os.Getenv("OKTA_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/okta
GET|POST /api/authorization/provider/okta/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/okta/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `okta` |
| Display name | Okta |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `okta` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`okta.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := okta.New(okta.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
