---
title: Todoist
description: Sign in with Todoist using the goauth `todoist` provider preset.
---

# Todoist

Use the [`providers/todoist`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/todoist) preset to add Todoist sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/todoist"
)

Providers: []goauth.Provider{
	todoist.New(todoist.Options{
		ClientID:     os.Getenv("TODOIST_CLIENT_ID"),
		ClientSecret: os.Getenv("TODOIST_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/todoist
GET|POST /api/authorization/provider/todoist/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/todoist/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `todoist` |
| Display name | Todoist |
| Type | `oauth` |
| Default scopes | `data:read` |
| Checks | State |
| Authorization URL | `https://todoist.com/oauth/authorize` |
| Token URL | `https://todoist.com/oauth/access_token` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `todoist` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`todoist.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := todoist.New(todoist.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
