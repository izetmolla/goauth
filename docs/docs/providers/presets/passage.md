---
title: Passage
description: Sign in with Passage using the goauth `passage` provider preset.
---

# Passage

Use the [`providers/passage`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/passage) preset to add Passage sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/passage"
)

Providers: []goauth.Provider{
	passage.New(passage.Options{
		ClientID:     os.Getenv("PASSAGE_CLIENT_ID"),
		ClientSecret: os.Getenv("PASSAGE_CLIENT_SECRET"),
		Issuer:       os.Getenv("PASSAGE_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/passage
GET|POST /api/authorization/provider/passage/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/passage/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `passage` |
| Display name | Passage |
| Type | `oidc` |
| Default scopes | `openid`, `email`, `profile` |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `passage` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`passage.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := passage.New(passage.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
