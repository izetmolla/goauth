---
title: Kakao
description: Sign in with Kakao using the goauth `kakao` provider preset.
---

# Kakao

Use the [`providers/kakao`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/kakao) preset to add Kakao sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/kakao"
)

Providers: []goauth.Provider{
	kakao.New(kakao.Options{
		ClientID:     os.Getenv("KAKAO_CLIENT_ID"),
		ClientSecret: os.Getenv("KAKAO_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/kakao
GET|POST /api/authorization/provider/kakao/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/kakao/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `kakao` |
| Display name | Kakao |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://kauth.kakao.com/oauth/authorize` |
| Token URL | `https://kauth.kakao.com/oauth/token` |
| Userinfo URL | `https://kapi.kakao.com/v2/user/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `kakao` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`kakao.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := kakao.New(kakao.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
