---
title: Azure AD / Entra ID
description: Microsoft sign-in with the Azure AD v2.0 endpoints and Microsoft Graph.
---

# Azure AD / Microsoft Entra ID

```go
import "github.com/izetmolla/goauth/providers/azuread"

Providers: []goauth.Provider{
	azuread.New(azuread.Options{
		ClientID:     os.Getenv("AZURE_CLIENT_ID"),
		ClientSecret: os.Getenv("AZURE_CLIENT_SECRET"),
		TenantID:     os.Getenv("AZURE_TENANT_ID"), // optional, defaults to "common"
	}),
},
```

Endpoints:

```text
GET /api/authorization/provider/azuread-v2            # start sign-in
GET /api/authorization/provider/azuread-v2/callback   # redirect URI
```

## Options

| Field | Required | Description |
|---|---|---|
| `ClientID` | yes | Application (client) ID |
| `ClientSecret` | yes | Client secret value |
| `TenantID` | no | Tenant GUID (your organization only), `common` (default: work and personal accounts), `organizations` (any work account) or `consumers` (personal only) |
| `Scopes` | no | Replaces the defaults `openid profile email User.Read` (`azuread.DefaultScopes`) |
| `AuthorizationParams` | no | Extra query parameters, for example `prompt=select_account` |
| `Profile` | no | Replaces `azuread.DefaultProfile` |

## What the preset configures

| Setting | Value |
|---|---|
| id | `azuread-v2` |
| Display name | `Azure Active Directory` |
| Authorize URL | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` |
| Token URL | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` |
| Userinfo | `https://graph.microsoft.com/v1.0/me` |
| Checks | PKCE, `state`, `nonce` |

## Azure portal setup

1. **Microsoft Entra ID → App registrations → New registration**.
2. Choose the supported account types (this decides which `TenantID` values make sense).
3. Add a **Web** redirect URI:

   ```text
   https://app.example.com/api/authorization/provider/azuread-v2/callback
   ```

4. **Certificates & secrets → New client secret**. Copy the **value** (not the secret id).
5. **API permissions**: delegated `User.Read` is enough for sign-in. Add more Graph permissions only if you need them.

## Profile fields

`ResolveUser` receives the Microsoft Graph `/me` response:

| Key | Example |
|---|---|
| `id` | Graph object id |
| `displayName` | `"Jane Doe"` |
| `givenName`, `surname` | `"Jane"`, `"Doe"` |
| `mail` | `"jane@contoso.com"` (can be null) |
| `userPrincipalName` | `"jane@contoso.com"` |
| `jobTitle`, `officeLocation` | organization fields |

Use `mail`, falling back to `userPrincipalName`. `mail` can be JSON `null`, so read both with a helper that returns `""` for anything that isn't a string:

```go
func str(v any) string { s, _ := v.(string); return s }

email := cmp.Or(str(p["mail"]), str(p["userPrincipalName"]))
```

## Mapping Azure groups to roles

Group membership is not in `/me`. Read it with the user's Graph access token (`GroupMember.Read.All` or `User.Read` with group claims configured), or manage roles in your own users table.

## Extra Graph permissions

Ask for more scopes and use the stored tokens:

```go
azuread.New(azuread.Options{
	ClientID:     id,
	ClientSecret: secret,
	TenantID:     tenant,
	Scopes:       []string{"openid", "profile", "email", "offline_access", "User.Read", "Calendars.Read"},
})
```

`offline_access` returns a refresh token. For granting extra scopes after sign-in, see [Provider connect](../guides/provider-connect.md).
