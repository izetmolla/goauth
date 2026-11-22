---
title: NetSuite
description: Sign in with NetSuite using the goauth `netsuite` provider preset.
---

# NetSuite

Use the [`providers/netsuite`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/netsuite) preset to add NetSuite sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/netsuite"
)

Providers: []goauth.Provider{
	netsuite.New(netsuite.Options{
		ClientID:     os.Getenv("NETSUITE_CLIENT_ID"),
		ClientSecret: os.Getenv("NETSUITE_CLIENT_SECRET"),
		AccountID: /* … */,
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/netsuite
GET|POST /api/authorization/provider/netsuite/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/netsuite/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `netsuite` |
| Display name | NetSuite |
| Type | `oauth` |
| Default scopes | `rest_webservices`, `restlets` |
| Checks | State |
| Authorization URL | `https://` |
| Token URL | `https://` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `AccountID` | see package | `string` |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `netsuite` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`netsuite.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := netsuite.New(netsuite.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
