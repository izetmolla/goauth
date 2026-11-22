---
title: Dropbox
description: Sign in with Dropbox using the goauth `dropbox` provider preset.
---

# Dropbox

Use the [`providers/dropbox`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/dropbox) preset to add Dropbox sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/dropbox"
)

Providers: []goauth.Provider{
	dropbox.New(dropbox.Options{
		ClientID:     os.Getenv("DROPBOX_CLIENT_ID"),
		ClientSecret: os.Getenv("DROPBOX_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/dropbox
GET|POST /api/authorization/provider/dropbox/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/dropbox/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `dropbox` |
| Display name | Dropbox |
| Type | `oauth` |
| Default scopes | `account_info.read` |
| Checks | State |
| Authorization URL | `https://www.dropbox.com/oauth2/authorize` |
| Token URL | `https://api.dropboxapi.com/oauth2/token` |
| Userinfo URL | `https://api.dropboxapi.com/2/users/get_current_account` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `dropbox` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`dropbox.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := dropbox.New(dropbox.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
