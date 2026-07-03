# Google provider

Google sign-in for [goauth](../../README.md) using OpenID Connect discovery.

## Usage

```go
import "github.com/izetmolla/goauth/providers/google"

auth, err := goauth.New(&goauth.Config{
	// ...
	Providers: []goauth.Provider{
		google.New(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")),
	},
})
```

That is the whole configuration. Endpoints:

```
GET /api/authorization/provider/google            # start sign-in (302 to Google)
GET /api/authorization/provider/google/callback   # OAuth callback
```

## What the preset configures

| Setting | Value |
|---------|-------|
| Provider ID | `google` |
| Type | OIDC — endpoints discovered from `https://accounts.google.com/.well-known/openid-configuration` |
| Scopes | `openid`, `email`, `profile` |
| Security checks | PKCE (S256) + `state` + `nonce` |
| Profile mapping | `sub` → ID, `name` → Name, `email` → Email, `picture` → Image |

## Google Cloud Console setup

1. Create OAuth 2.0 credentials at [console.cloud.google.com/apis/credentials](https://console.cloud.google.com/apis/credentials) (type *Web application*).
2. Add the authorized redirect URI, which must match your deployment exactly:

   ```
   https://your-app.example.com/api/authorization/provider/google/callback
   ```

   For local development: `http://localhost:3000/api/authorization/provider/google/callback`.
3. Put the client ID and secret into `google.New(...)`.

The redirect URI is derived from `Config.AuthURL` (or the request's `Host`/`X-Forwarded-Host` when `AuthURL` is empty), so make sure `AuthURL` matches what you registered.

## Customizing

`google.New` returns a `*goauth.OAuthProvider` under the hood; for extra scopes or parameters, construct the provider yourself (see [providers/README.md](../README.md#writing-a-custom-oauthoidc-provider)) with `Issuer: "https://accounts.google.com"`, e.g. adding `AuthorizationParams: url.Values{"access_type": {"offline"}, "prompt": {"consent"}}` to receive a refresh token from Google.
