---
title: Atlassian
description: Sign in with Atlassian using the goauth `atlassian` provider preset.
---

# Atlassian

Use the [`providers/atlassian`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/atlassian) preset to add Atlassian sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/atlassian"
)

Providers: []goauth.Provider{
	atlassian.New(atlassian.Options{
		ClientID:     os.Getenv("ATLASSIAN_CLIENT_ID"),
		ClientSecret: os.Getenv("ATLASSIAN_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/atlassian
GET|POST /api/authorization/provider/atlassian/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/atlassian/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `atlassian` |
| Display name | Atlassian |
| Type | `oauth` |
| Default scopes | `read:me` |
| Checks | State |
| Authorization URL | `https://auth.atlassian.com/authorize` |
| Token URL | `https://auth.atlassian.com/oauth/token` |
| Userinfo URL | `https://api.atlassian.com/me` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `atlassian` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`atlassian.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := atlassian.New(atlassian.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
