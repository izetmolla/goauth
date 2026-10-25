---
title: Google
description: Sign in with Google using OpenID Connect discovery, PKCE, state and nonce.
---

# Google

```go
import "github.com/izetmolla/goauth/providers/google"

Providers: []goauth.Provider{
	google.New(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")),
},
```

## What the preset configures

| Setting | Value |
|---|---|
| id | `google` |
| Type | `oidc` |
| Issuer | `https://accounts.google.com` (endpoints found by OIDC discovery) |
| Scopes | `openid email profile` |
| Checks | PKCE, `state`, `nonce` |

## Google Cloud setup

1. Open [Google Cloud console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials).
2. Configure the **OAuth consent screen** (app name, support email, scopes `openid`, `email`, `profile`).
3. **Create credentials → OAuth client ID → Web application**.
4. Add authorized redirect URIs for each environment:

   ```text
   http://localhost:3000/api/authorization/provider/google/callback
   https://app.example.com/api/authorization/provider/google/callback
   ```

## Profile fields

`ResolveUser` receives Google's userinfo response:

| Key | Example |
|---|---|
| `sub` | `"110248495921238986420"` (stable Google user id) |
| `email` | `"jane@gmail.com"` |
| `email_verified` | `true` |
| `name` | `"Jane Doe"` |
| `given_name`, `family_name` | `"Jane"`, `"Doe"` |
| `picture` | avatar URL |
| `hd` | Google Workspace domain, for example `"example.com"` (absent for gmail.com) |
| `provider`, `providerType` | `"google"`, `"oidc"` (added by goauth) |

## Restrict to a Google Workspace domain

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	if p["hd"] != "example.com" || p["email_verified"] != true {
		return nil, false, errors.New("use your @example.com account")
	}
	return findOrCreate(ctx, p)
},
```

Use `sub`, not `email`, as the permanent identifier if users can change their address.

## Customizing

`google.New` returns a `*goauth.OAuthProvider`, so you can adjust it, for example to always show the account chooser:

```go
g := google.New(id, secret).(*goauth.OAuthProvider)
g.AuthorizationParams = url.Values{"prompt": {"select_account"}}
// Hint the Workspace domain on the Google sign-in screen:
g.AuthorizationParams.Set("hd", "example.com")
```

To get a Google refresh token (for calling Google APIs offline), request offline access:

```go
g.AuthorizationParams = url.Values{"access_type": {"offline"}, "prompt": {"consent"}}
```

The token is stored in the session's `account` column. See [Sessions and Redis](../guides/sessions-and-redis.md#the-session-model).
