---
title: Naver
description: Sign in with Naver using the goauth `naver` provider preset.
---

# Naver

Use the [`providers/naver`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/naver) preset to add Naver sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/naver"
)

Providers: []goauth.Provider{
	naver.New(naver.Options{
		ClientID:     os.Getenv("NAVER_CLIENT_ID"),
		ClientSecret: os.Getenv("NAVER_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/naver
GET|POST /api/authorization/provider/naver/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/naver/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `naver` |
| Display name | Naver |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://nid.naver.com/oauth2.0/authorize` |
| Token URL | `https://nid.naver.com/oauth2.0/token` |
| Userinfo URL | `https://openapi.naver.com/v1/nid/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `naver` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`naver.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := naver.New(naver.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
