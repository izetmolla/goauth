---
title: Step by step
description: Add a custom OAuth 2.0 / OIDC provider to your app in six steps, from registering the app to the first sign-in.
---

# Adding a custom provider, step by step

This guide adds a fictional provider called **Acme ID** (`https://id.acme.example`). Replace the URLs and field names with your provider's.

## Step 1: Register your app at the provider

In the provider's developer console:

1. Create an OAuth application (sometimes called a "client" or "app registration").
2. Set the **redirect URI** (also called callback URL) to:

   ```text
   http://localhost:3000/api/authorization/provider/acme/callback
   https://app.example.com/api/authorization/provider/acme/callback
   ```

   The last path segment before `/callback` is your **provider id**. Pick it now: lowercase, URL-safe, for example `acme`.

3. Copy the **client ID** and **client secret** into environment variables:

   ```bash
   export ACME_CLIENT_ID="..."
   export ACME_CLIENT_SECRET="..."
   ```

## Step 2: Find the endpoints

**If the provider supports OpenID Connect**, check its discovery document:

```bash
curl -s https://id.acme.example/.well-known/openid-configuration | jq '{authorization_endpoint, token_endpoint, userinfo_endpoint}'
```

If that works, you only need the issuer (`https://id.acme.example`). Skip to step 3 and set `Issuer`.

**Otherwise**, find three URLs in the provider's documentation:

| Endpoint | Acme value | What goauth does with it |
|---|---|---|
| Authorize | `https://id.acme.example/oauth/authorize` | Redirects the browser here to sign in |
| Token | `https://id.acme.example/oauth/token` | Exchanges the authorization code for tokens (server to server) |
| Userinfo | `https://id.acme.example/api/me` | Fetches the user's profile with the access token |

## Step 3: Define the provider

```go
acme := &goauth.OAuthProvider{
	ProviderID:   "acme",                // must match the redirect URI
	DisplayName:  "Acme ID",             // shown in GET /providers
	Kind:         goauth.ProviderOAuth,  // ProviderOIDC when using Issuer
	ClientID:     os.Getenv("ACME_CLIENT_ID"),
	ClientSecret: os.Getenv("ACME_CLIENT_SECRET"),

	// Plain OAuth 2.0: explicit endpoints.
	AuthorizationURL: "https://id.acme.example/oauth/authorize",
	TokenURL:         "https://id.acme.example/oauth/token",
	UserInfoURL:      "https://id.acme.example/api/me",
	// OIDC alternative: Issuer: "https://id.acme.example",

	Scopes: []string{"openid", "email", "profile"},
	Checks: []goauth.Check{goauth.CheckPKCE, goauth.CheckState},

	Profile: acmeProfile, // step 4
}
```

### Every field

| Field | Required | Description |
|---|---|---|
| `ProviderID` | yes | URL id, for example `acme` |
| `DisplayName` | yes | Shown in `/providers` |
| `Kind` | yes | `goauth.ProviderOAuth` or `goauth.ProviderOIDC` |
| `ClientID`, `ClientSecret` | yes | From the provider's developer console |
| `Issuer` | OIDC | Enables discovery of the authorize, token and userinfo URLs |
| `AuthorizationURL`, `TokenURL`, `UserInfoURL` | without `Issuer` | Explicit endpoints; explicit values win over discovery |
| `AuthorizationParams` | no | Extra query parameters for the authorize request, for example `prompt=consent` |
| `Scopes` | no | Space-joined into `scope` |
| `Checks` | no | Any of `goauth.CheckPKCE`, `CheckState`, `CheckNonce` |
| `Profile` | yes | Maps the userinfo JSON to a `*goauth.OAuthUser` |
| `AuthorizationStyle` | no | `"body"` (default): client credentials in the form; `"header"`: HTTP Basic |

### Choosing checks

- **`CheckState`**: always enable it. It protects the callback from CSRF.
- **`CheckPKCE`**: enable it if the provider supports PKCE (most do, including GitHub, Google, Microsoft, Okta, Keycloak). If the token exchange fails with `invalid_grant` or "code_verifier not supported", remove it.
- **`CheckNonce`**: only for OpenID Connect providers.

### Client authentication

Most providers accept the client ID and secret in the token request body (the default). If the provider documentation says "HTTP Basic" or `client_secret_basic`, set:

```go
AuthorizationStyle: "header",
```

## Step 4: Map the profile

`Profile` turns the provider's userinfo JSON into a `*goauth.OAuthUser`. First look at what the provider returns:

```bash
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" https://id.acme.example/api/me
```

```json
{"user_id": "acme-42", "email": "jane@acme.example", "full_name": "Jane Doe", "avatar": "https://..."}
```

Then map it:

```go
func acmeProfile(p goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error) {
	id, _ := p["user_id"].(string)
	if id == "" {
		return nil, errors.New("acme: profile has no user_id")
	}
	email, _ := p["email"].(string)
	name, _ := p["full_name"].(string)
	return &goauth.OAuthUser{ID: id, Email: email, Name: name}, nil
}
```

Rules of thumb:

- **`ID` must be stable and unique** at the provider. It is stored as `Account.ProviderAccountID`.
- Read values with type assertions (`p["x"].(string)`) so a missing or `null` field gives `""` instead of `"<nil>"`.
- JSON numbers arrive as `float64`. Convert ids with `strconv.FormatInt(int64(v), 10)`.
- Return an error to abort the sign-in. The message is shown on the callback page.

`ResolveUser` receives the **raw** profile (plus `provider` and `providerType`), not the `OAuthUser`. Keep the two in sync: if you read `email` in `Profile`, read the same key in `ResolveUser`.

## Step 5: Register it and handle the user

```go
auth, err := goauth.New(&goauth.Config{
	JWTSecret: os.Getenv("JWT_SECRET"),
	AuthURL:   "http://localhost:3000",
	DB:        db,
	Providers: []goauth.Provider{acme},
	ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
		if p["provider"] == "acme" {
			email, _ := p["email"].(string)
			return findOrCreateUser(ctx, db, email)
		}
		return nil, false, errors.New("unknown provider")
	},
})
```

## Step 6: Sign in

Start the app and check that the provider is listed:

```bash
curl -s localhost:3000/api/authorization/providers | jq
```

```json
[{"id": "acme", "name": "Acme ID", "type": "oauth",
  "signinUrl": "http://localhost:3000/api/authorization/provider/acme",
  "callbackUrl": "http://localhost:3000/api/authorization/provider/acme/callback"}]
```

Inspect the authorization URL goauth builds:

```bash
curl -s 'localhost:3000/api/authorization/provider/acme?json=true' | jq -r .url
```

```text
https://id.acme.example/oauth/authorize?client_id=...&code_challenge=...&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauthorization%2Fprovider%2Facme%2Fcallback&response_type=code&scope=openid+email+profile&state=...
```

Then open `http://localhost:3000/api/authorization/provider/acme` in a browser and sign in.

## Troubleshooting

| Error on the callback page | Cause and fix |
|---|---|
| `redirect_uri_mismatch` (at the provider) | The registered redirect URI differs from `callbackUrl` in `/providers`: check scheme, host, port, provider id |
| `Token exchange failed: token exchange: status 400: {"error":"invalid_client"...}` | Wrong secret, or the provider wants HTTP Basic: set `AuthorizationStyle: "header"` |
| `Token exchange failed: ... "invalid_grant"` | Code reused or expired, wrong redirect URI, or PKCE not supported: remove `goauth.CheckPKCE` |
| `Userinfo failed: userinfo: status 401: ...` | Missing scope, or the userinfo URL needs a different API version |
| `Profile mapping failed: ...` | Your `Profile` returned an error; log `p` to see the real field names |
| `State mismatch` | The state cookie was lost: the callback host differs from the sign-in host, or more than 15 minutes passed |
| `Provider missing AuthorizationURL` | No `Issuer` and no `AuthorizationURL` set |

## Next

- Make it reusable across apps: [Reusable package](./reusable-package.md)
- Test it without a browser: [Testing](./testing.md)
