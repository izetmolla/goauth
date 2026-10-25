---
title: Provider connect
description: Link an extra OAuth account or extra scopes (for example Microsoft Graph mail access) to an existing record.
---

# Provider connect (account linking)

A **connect** flow runs OAuth without signing the user in. Instead, goauth hands you the provider account and tokens so you can attach them to something in your app.

Typical uses:

- A signed-in user grants extra Microsoft Graph scopes (`Mail.Send`, `Files.Read`) for an integration.
- An admin connects a shared mailbox or calendar to a project.
- A user links a second provider to their account.

## Configure `OnProviderConnect`

```go
auth, err := goauth.New(&goauth.Config{
	JWTSecret:   os.Getenv("JWT_SECRET"),
	DB:          db,
	ResolveUser: resolveUser,
	Providers: []goauth.Provider{
		azuread.New(azuread.Options{
			ClientID:     os.Getenv("AZURE_CLIENT_ID"),
			ClientSecret: os.Getenv("AZURE_CLIENT_SECRET"),
			TenantID:     os.Getenv("AZURE_TENANT_ID"),
			Scopes:       []string{"openid", "profile", "email", "offline_access", "User.Read", "Mail.Send"},
		}),
	},
	OnProviderConnect: func(ctx context.Context, resourceID string, acc *goauth.Account, user *goauth.User, providerID string) error {
		return db.WithContext(ctx).Exec(`
			INSERT INTO integrations (resource_id, provider, provider_account_id, user_id,
			                          access_token, refresh_token, scope, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, to_timestamp(?))
			ON CONFLICT (resource_id, provider) DO UPDATE SET
			  access_token = EXCLUDED.access_token,
			  refresh_token = EXCLUDED.refresh_token,
			  scope = EXCLUDED.scope,
			  expires_at = EXCLUDED.expires_at`,
			resourceID, providerID, acc.ProviderAccountID, user.ID,
			acc.AccessToken, acc.RefreshToken, acc.Scope, acc.ExpiresAt,
		).Error
	},
})
```

Arguments:

| Argument | Value |
|---|---|
| `resourceID` | The `resource_id` UUID from the start URL |
| `acc` | `*goauth.Account`: provider id, provider account id, access/refresh/ID tokens, scope, expiry |
| `user` | The user `ResolveUser` returned for the connecting account |
| `providerID` | For example `azuread-v2` |

Returning an error shows it on the callback page.

## Start a connect flow

Add `connect=1` and a `resource_id` UUID to the sign-in URL:

```text
/api/authorization/provider/azuread-v2?connect=1&resource_id=7d3c5c8e-2a0e-4c55-9f43-5d9a8a2b7f10
```

1. goauth stores a **signed** connect-intent cookie and the resource id (15 minute lifetime).
2. The provider runs its normal consent screen.
3. On callback, goauth verifies the signed intent, calls `ResolveUser`, then `OnProviderConnect`.
4. **No session is created and no session cookie is set.**
5. The callback page shows a success message and a **Close this tab** button.

`resource_id` must be a valid UUID. Without it, the flow still completes but `OnProviderConnect` is not called.

## Open it in a popup

When the callback page has an opener, it posts a message on success:

```js
function connectMicrosoft(resourceId) {
  return new Promise((resolve) => {
    window.open(
      `/api/authorization/provider/azuread-v2?connect=1&resource_id=${resourceId}`,
      'connect',
      'width=520,height=680',
    );
    window.addEventListener('message', function onMessage(e) {
      if (e.origin !== location.origin || e.data?.type !== 'microsoft-connect-completed') return;
      window.removeEventListener('message', onMessage);
      resolve(e.data.resource_id);
    });
  });
}
```

The message type is `microsoft-connect-completed` for every provider.

## Protecting the connect flow

The connect start URL is public, like any sign-in URL. Before trusting a connection, check in `OnProviderConnect` that the user is allowed to modify `resourceID`:

```go
OnProviderConnect: func(ctx context.Context, resourceID string, acc *goauth.Account, user *goauth.User, providerID string) error {
	var ok bool
	db.WithContext(ctx).Raw(
		`SELECT EXISTS (SELECT 1 FROM projects WHERE id = ? AND owner_id = ?)`,
		resourceID, user.ID,
	).Scan(&ok)
	if !ok {
		return errors.New("you cannot connect an account to this project")
	}
	return saveIntegration(ctx, resourceID, acc, user, providerID)
},
```

## Low-level helpers

`auth.SetFlowIntentCookie(w, r, goauth.FlowIntentConnect)` and `auth.SetConnectResourceCookie(w, r, resourceID)` are the functions the start endpoint uses for `?connect=1`. The start endpoint clears both cookies at the beginning of every flow, so setting them yourself and then redirecting to `/provider/{id}` has no effect. Use the `connect=1&resource_id=...` query parameters instead.
