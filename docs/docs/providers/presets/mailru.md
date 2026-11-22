---
title: Mail.ru
description: Sign in with Mail.ru using the goauth `mailru` provider preset.
---

# Mail.ru

Use the [`providers/mailru`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/mailru) preset to add Mail.ru sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/mailru"
)

Providers: []goauth.Provider{
	mailru.New(mailru.Options{
		ClientID:     os.Getenv("MAILRU_CLIENT_ID"),
		ClientSecret: os.Getenv("MAILRU_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/mailru
GET|POST /api/authorization/provider/mailru/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/mailru/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `mailru` |
| Display name | Mail.ru |
| Type | `oauth` |
| Default scopes | `userinfo` |
| Checks | State |
| Authorization URL | `https://oauth.mail.ru/login` |
| Token URL | `https://oauth.mail.ru/token` |
| Userinfo URL | `https://oauth.mail.ru/userinfo` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `mailru` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`mailru.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := mailru.New(mailru.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
