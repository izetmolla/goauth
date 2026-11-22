---
title: Notion
description: Sign in with Notion using the goauth `notion` provider preset.
---

# Notion

Use the [`providers/notion`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/notion) preset to add Notion sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/notion"
)

Providers: []goauth.Provider{
	notion.New(notion.Options{
		ClientID:     os.Getenv("NOTION_CLIENT_ID"),
		ClientSecret: os.Getenv("NOTION_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/notion
GET|POST /api/authorization/provider/notion/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/notion/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `notion` |
| Display name | Notion |
| Type | `oauth` |
| Default scopes | _(provider default)_ |
| Checks | State |
| Authorization URL | `https://api.notion.com/v1/oauth/authorize` |
| Token URL | `https://api.notion.com/v1/oauth/token` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `notion` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`notion.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := notion.New(notion.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
