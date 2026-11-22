---
title: Salesforce
description: Sign in with Salesforce using the goauth `salesforce` provider preset.
---

# Salesforce

Use the [`providers/salesforce`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/salesforce) preset to add Salesforce sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/salesforce"
)

Providers: []goauth.Provider{
	salesforce.New(salesforce.Options{
		ClientID:     os.Getenv("SALESFORCE_CLIENT_ID"),
		ClientSecret: os.Getenv("SALESFORCE_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/salesforce
GET|POST /api/authorization/provider/salesforce/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/salesforce/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `salesforce` |
| Display name | Salesforce |
| Type | `oidc` |
| Default scopes | `openid`, `id`, `profile`, `email` |
| Checks | PKCE, State, Nonce |
| Issuer | `https://login.salesforce.com` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `salesforce` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`salesforce.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := salesforce.New(salesforce.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
