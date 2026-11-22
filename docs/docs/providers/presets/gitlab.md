---
title: GitLab
description: Sign in with GitLab using the goauth `gitlab` provider preset.
---

# GitLab

Use the [`providers/gitlab`](https://pkg.go.dev/github.com/izetmolla/goauth/providers/gitlab) preset to add GitLab sign-in.

## Usage

```go
import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/gitlab"
)

Providers: []goauth.Provider{
	gitlab.New(gitlab.Options{
		ClientID:     os.Getenv("GITLAB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITLAB_CLIENT_SECRET"),
		BaseURL: /* … */,
	}),
},
```

## Endpoints

```text
GET|POST /api/authorization/provider/gitlab
GET|POST /api/authorization/provider/gitlab/callback
```

Register this redirect URI with the identity provider:

```text
https://app.example.com/api/authorization/provider/gitlab/callback
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `gitlab` |
| Display name | GitLab |
| Type | `oauth` |
| Default scopes | `read_user` |
| Checks | State |

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | OAuth client id |
| `ClientSecret` | yes | OAuth client secret |
| `BaseURL` | see package | `string` |
| `Scopes` | no | Replaces the default scopes |
| `AuthorizationParams` | no | Extra authorize-query parameters |


## ResolveUser

After a successful callback, goauth calls your `Config.ResolveUser` with the provider profile (plus `provider` = `gitlab` and `providerType`). Map it to a row in your users table — see [OAuth sign-in](../../guides/oauth-sign-in.md).

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	return findOrCreate(ctx, p)
},
```

## Customizing

`gitlab.New` returns a `*goauth.OAuthProvider`, so you can tweak scopes or authorization parameters after construction when needed:

```go
p := gitlab.New(gitlab.Options{ /* ... */ }).(*goauth.OAuthProvider)
// p.Scopes = []string{"..."}
```

More provider model details: [Providers overview](../overview.md).
