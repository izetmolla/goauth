---
title: BankID Norge
description: Sign in with BankID Norge using the goauth `bankidno` provider preset.
---

# BankID Norge

Use the [`providers/bankidno`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/bankidno) preset to add BankID Norge sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/bankidno"
)

Providers: []goauth.Provider{
	bankidno.New(bankidno.Options{
		ClientID:     os.Getenv("BANKIDNO_CLIENT_ID"),
		ClientSecret: os.Getenv("BANKIDNO_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/bankid-no
GET|POST /api/authorization/provider/bankid-no/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/bankid-no/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `bankid-no` |
| Display name | BankID Norge |
| Type | `oidc` |
| Default scopes | `openid`, `profile` |
| Checks | PKCE, State, Nonce |
| Issuer | `https://auth.bankid.no/auth/realms/prod` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `bankid-no` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`bankidno.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := bankidno.New(bankidno.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
