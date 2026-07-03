# Credentials provider

Username/password (or any custom field set) authentication for [goauth](../../README.md). You supply the `Authorize` function that validates the credentials; goauth handles the endpoint, CSRF protection, sessions, and tokens.

## Usage

```go
import "github.com/izetmolla/goauth/providers/credentials"

auth, err := goauth.New(&goauth.Config{
	// ...
	Providers: []goauth.Provider{
		credentials.New(credentials.Options{
			Fields: []goauth.CredentialField{
				{Name: "email", Label: "Email", Type: "email", Placeholder: "you@example.com"},
				{Name: "password", Label: "Password", Type: "password"},
			},
			Authorize: func(ctx context.Context, creds map[string]string, r *http.Request) (*goauth.OAuthUser, error) {
				user, err := myDB.FindUserByEmail(ctx, creds["email"])
				if err != nil {
					return nil, nil // (nil, nil) → generic invalid-credentials response
				}
				if !goauth.CheckPassword(user.PasswordHash, creds["password"]) {
					return nil, nil
				}
				return &goauth.OAuthUser{ID: user.ID, Email: user.Email, Name: user.Name}, nil
			},
		}),
	},
})
```

Sign-in endpoint (POST only):

```
POST /api/authorization/provider/credentials
```

## Options

| Field | Required | Description |
|-------|----------|-------------|
| `Authorize` | yes | Validates the submitted credentials and returns the user, or `nil` to reject |
| `ID` | no | Route id, defaults to `credentials` |
| `Name` | no | Display name, defaults to `Credentials` |
| `Fields` | no | Describes the sign-in form inputs; returned by `GET /providers` so frontends can render the form dynamically (mirrors the Auth.js `credentials` map) |

## Behavior notes

- **CSRF**: browser (cookie) sign-ins must echo the signed double-submit `csrfToken` in the request body. Token-flow clients (header `X-Auth-Flow: token` or `?flow=token`) are exempt, since they are not cookie-based.
- **Method**: only `POST` is accepted; other methods get `405`.
- **Password hashing**: use `goauth.HashPassword` / `goauth.CheckPassword` (PBKDF2-SHA256, 600k iterations, self-describing `$pbkdf2-sha256$...` format) for storage.

## Pairing with LDAP

The [LDAP client](../ldap/README.md) slots into `Authorize` directly — validate against the directory, then map to your app user:

```go
Authorize: func(ctx context.Context, creds map[string]string, r *http.Request) (*goauth.OAuthUser, error) {
	entry, err := ldapClient.Login(creds["username"], creds["password"])
	if err != nil {
		return nil, nil
	}
	return &goauth.OAuthUser{ID: entry.Identity(), Email: entry.Email, Name: entry.Name}, nil
},
```
