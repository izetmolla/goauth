---
title: Slack
description: Sign in with Slack using the goauth `slack` provider preset.
---

# Slack

Use the [`providers/slack`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/slack) preset to add Slack sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/slack"
)

Providers: []goauth.Provider{
	slack.New(slack.Options{
		ClientID:     os.Getenv("SLACK_CLIENT_ID"),
		ClientSecret: os.Getenv("SLACK_CLIENT_SECRET"),
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/slack
GET|POST /api/authorization/provider/slack/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/slack/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `slack` |
| Display name | Slack |
| Type | `oidc` |
| Default scopes | `openid`, `profile`, `email` |
| Checks | Nonce |
| Issuer | `https://slack.com` |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `slack` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`slack.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := slack.New(slack.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
