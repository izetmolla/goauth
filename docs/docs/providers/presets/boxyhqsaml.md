---
title: BoxyHQ SAML
description: Sign in with BoxyHQ SAML using the goauth `boxyhqsaml` provider preset.
---

# BoxyHQ SAML

Use the [`providers/boxyhqsaml`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/boxyhqsaml) preset to add BoxyHQ SAML sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/boxyhqsaml"
)

Providers: []goauth.Provider{
	boxyhqsaml.New(boxyhqsaml.Options{
		ClientID:     os.Getenv("BOXYHQSAML_CLIENT_ID"),
		ClientSecret: os.Getenv("BOXYHQSAML_CLIENT_SECRET"),
		Issuer:       os.Getenv("BOXYHQSAML_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/boxyhq-saml
GET|POST /api/authorization/provider/boxyhq-saml/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/boxyhq-saml/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `boxyhq-saml` |
| Display name | BoxyHQ SAML |
| Type | `oauth` |
| Default scopes | `openid` |
| Checks | State |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `boxyhq-saml` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`boxyhqsaml.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := boxyhqsaml.New(boxyhqsaml.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
