# Azure AD / Microsoft Entra ID provider

Microsoft sign-in for [goauth](../../README.md) using the Azure AD **v2.0** OAuth/OIDC endpoints and the Microsoft Graph `/me` endpoint for profile data.

## Usage

```go
import "github.com/izetmolla/goauth/providers/azuread"

auth, err := goauth.New(&goauth.Config{
	// ...
	Providers: []goauth.Provider{
		azuread.New(azuread.Options{
			ClientID:     os.Getenv("AZURE_CLIENT_ID"),
			ClientSecret: os.Getenv("AZURE_CLIENT_SECRET"),
			TenantID:     os.Getenv("AZURE_TENANT_ID"), // optional, defaults to "common"
		}),
	},
})
```

Endpoints:

```
GET /api/authorization/provider/azuread-v2            # start sign-in
GET /api/authorization/provider/azuread-v2/callback   # OAuth callback
```

## Options

| Field | Required | Description |
|-------|----------|-------------|
| `ClientID` | yes | Application (client) ID from the Azure portal |
| `ClientSecret` | yes | Client secret generated in the Azure portal |
| `TenantID` | no | Who may sign in: a tenant GUID (single-tenant), `common` (any AAD or personal account, **default**), `organizations` (any AAD account), or `consumers` (personal accounts only) |
| `Scopes` | no | Overrides the defaults `openid profile email User.Read`; add Graph permissions like `Files.Read`, `Mail.Send`, `offline_access` here |
| `AuthorizationParams` | no | Extra query parameters appended to the authorize request (e.g. `prompt=select_account`) |
| `Profile` | no | Overrides `azuread.DefaultProfile` for custom user mapping |

## What the preset configures

| Setting | Value |
|---------|-------|
| Provider ID | `azuread-v2` |
| Authorize / token URLs | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/{authorize,token}` |
| User info | `https://graph.microsoft.com/v1.0/me` |
| Security checks | PKCE (S256) + `state` + `nonce` |
| Profile mapping | Handles both OIDC id_token claims and Graph fields: `sub`/`id`/`oid` → ID, `name`/`displayName` → Name, `email`/`mail`/`userPrincipalName` → Email, `givenName`/`surname` → first/last name |

## Azure portal setup

1. Register an application under **Microsoft Entra ID → App registrations**.
2. Add a **Web** redirect URI matching your deployment:

   ```
   https://your-app.example.com/api/authorization/provider/azuread-v2/callback
   ```

3. Create a client secret under **Certificates & secrets**.
4. Grant the API permissions your scopes require (delegated `User.Read` is included by default).

## Connect flow (linking extra scopes)

Azure AD works with goauth's provider-**connect** flow: send a signed-in user to

```
/api/authorization/provider/azuread-v2?connect=1&resource_id=<uuid>
```

and after consent the `Config.OnProviderConnect` callback receives the `resource_id`, the OAuth `Account` (with the granted tokens/scopes), and the user — useful for attaching Microsoft Graph access (mail, files, calendar) to an existing account. Include the extra Graph scopes and `offline_access` in `Options.Scopes` to receive a refresh token.
