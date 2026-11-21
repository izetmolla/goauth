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

## How sign-in works

`POST /api/authorization/provider/credentials` (form or JSON body, with `csrfToken`) calls `Authorize`, creates a session, sets the session cookie and returns the tokens. Set `Register` to add sign-up at `POST .../register`. Return a `*goauth.CredentialsError` for messages the user should see.

The [built-in sign-in page](../guides/sign-in-page.md) renders the form for you. Full details, including the JSON responses and the `X-Auth-Flow: token` mode for mobile clients, are on that page.

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

## Second factor and passkeys

After a successful password check, users with [Authenticator MFA](../guides/mfa-totp.md) enrolled receive `MFA_REQUIRED` until they verify a TOTP code. Passkeys are a separate primary sign-in method — see [Passkey](./passkey.md).
