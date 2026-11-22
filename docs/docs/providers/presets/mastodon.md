---
title: Mastodon
description: Sign in with Mastodon using the goauth `mastodon` provider preset.
---

# Mastodon

Use the [`providers/mastodon`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/mastodon) preset to add Mastodon sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/mastodon"
)

Providers: []goauth.Provider{
	mastodon.New(mastodon.Options{
		ClientID:     os.Getenv("MASTODON_CLIENT_ID"),
		ClientSecret: os.Getenv("MASTODON_CLIENT_SECRET"),
		Issuer:       os.Getenv("MASTODON_ISSUER"), // required OIDC issuer URL
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/mastodon
GET|POST /api/authorization/provider/mastodon/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/mastodon/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `mastodon` |
| Display name | Mastodon |
| Type | `oauth` |
| Default scopes | `read:accounts` |
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

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `mastodon` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`mastodon.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := mastodon.New(mastodon.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
