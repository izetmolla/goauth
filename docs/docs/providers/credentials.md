---
title: Credentials provider
description: Describe a username/password form with the credentials provider.
---

# Credentials provider

The credentials provider describes a form-based sign-in method (email and password, employee number and PIN, ...) so that it is listed alongside your OAuth providers.

```go
import "github.com/izetmolla/goauth/providers/credentials"

Providers: []goauth.Provider{
	google.New(googleID, googleSecret),
	credentials.New(credentials.Options{
		ID:   "credentials", // default "credentials"
		Name: "Email",       // default "Credentials"
		Fields: []goauth.CredentialField{
			{Name: "email", Label: "Email", Type: "email", Placeholder: "jane@example.com"},
			{Name: "password", Label: "Password", Type: "password"},
		},
		Authorize: func(ctx context.Context, c map[string]string, r *http.Request) (*goauth.OAuthUser, error) {
			return verifyPassword(ctx, c["email"], c["password"])
		},
	}),
},
```

`GET /api/authorization/providers` then includes:

```json
{
  "id": "credentials",
  "name": "Email",
  "type": "credentials",
  "signinUrl": "http://localhost:3000/api/authorization/provider/credentials",
  "callbackUrl": "http://localhost:3000/api/authorization/provider/credentials/callback"
}
```

## Current status

The provider's endpoint:

- accepts only `POST` (`405` otherwise),
- requires a valid double-submit CSRF token in the `csrfToken` form field for cookie-based requests (token-flow requests with `X-Auth-Flow: token` or `?flow=token` skip it),
- but does **not yet** call `Authorize` or create a session.

Until it does, implement password sign-in with your own handler, as shown in [Credentials sign-in](../guides/credentials-login.md). That handler gives you the same result: a session, a token pair and a session cookie.

## Using the field definitions in your UI

`CredentialField` mirrors the Auth.js `credentials` map, so you can render a form from your own config:

```go
fields := []goauth.CredentialField{
	{Name: "email", Label: "Email", Type: "email"},
	{Name: "password", Label: "Password", Type: "password"},
}

mux.HandleFunc("GET /api/login/fields", func(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(fields)
})
```

## Combining with LDAP

For directory accounts, verify the password with the [LDAP client](./ldap.md) inside your sign-in handler.
