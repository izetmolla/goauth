---
title: Google
description: Sign in with Google using the goauth `google` provider preset.
---

# Google

Use the [`providers/google`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/google) preset to add Google sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/google"
)

Providers: []goauth.Provider{
	google.New(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")),
},
```

Detailed Google Cloud setup: [Google](../google.md).

## Endpoints

```text
GET|POST /api/authorization/provider/google
GET|POST /api/authorization/provider/google/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/google/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `google` |
| Display name | Google |
| Type | `oidc` |
| Default scopes | `openid`, `email`, `profile` |
| Checks | PKCE, State, Nonce |
| Issuer | `https://accounts.google.com` |

## Options

`google.New` takes `(clientID, clientSecret string)` rather than an `Options` struct.

## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `google` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

```go
g := google.New(id, secret).(*goauth.OAuthProvider)
g.AuthorizationParams = url.Values{"prompt": {"select_account"}}
```

More provider model details: [Providers overview](../overview.md). Detailed setup: [Google](../google.md).
