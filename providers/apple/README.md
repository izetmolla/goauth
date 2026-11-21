# Apple provider

Sign in with Apple for [goauth](../../README.md) using OpenID Connect. Endpoints are set explicitly (Apple has no usable userinfo URL); the profile is taken from the `id_token`. Callbacks use `response_mode=form_post`, which goauth already merges into the callback query.

## Usage

```go
import "github.com/izetmolla/goauth/providers/apple"

auth, err := goauth.New(&goauth.Config{
	// ...
	Providers: []goauth.Provider{
		apple.New(apple.Options{
			ClientID:     os.Getenv("APPLE_CLIENT_ID"),
			ClientSecret: os.Getenv("APPLE_CLIENT_SECRET"), // JWT client secret
		}),
	},
})
```

```
GET  /api/authorization/provider/apple            # start sign-in
POST /api/authorization/provider/apple/callback   # form_post callback
```

## Notes

- Apple requires HTTPS redirect URIs (no localhost HTTP).
- The client secret must be a JWT signed with your Apple private key.
- Name is only returned the first time the user consents; afterward the `id_token` typically has `sub` + `email` only.
