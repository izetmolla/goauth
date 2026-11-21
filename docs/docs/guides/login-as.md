---
title: Login as another user
description: Let admins impersonate another account with a logged_by audit trail on sessions and JWTs.
---

# Login as another user

Admins (or any roles you configure) can open a session as another user:

```text
GET|POST /api/authorization/login_as?user_id=<target-user-id>
```

The feature is **off by default**. When enabled, a successful call:

1. Checks that the caller is signed in and has an allowed role.
2. Creates a **new** session for the target user with `logged_by` = admin id.
3. Issues access and refresh JWTs that include a `logged_by` object.
4. Sets the session cookie and (for browsers) runs the standard callback page so **localStorage** is updated and the user is **redirected** to `UI.DefaultRedirect`.

## 1. Enable

```go
auth, err := goauth.New(&goauth.Config{
	JWTSecret: secret,
	DB:        db,
	UI:        goauth.UIOptions{DefaultRedirect: "/"},
	LoginAs: goauth.LoginAsOptions{
		Enabled: true,
		Roles:   []string{"admin", "superadmin"},
		ResolveUser: func(ctx context.Context, userID string) (*goauth.LoginAsUser, error) {
			u, err := users.FindByID(ctx, userID)
			if err != nil || u == nil {
				return nil, err // or (nil, nil) when not found
			}
			return &goauth.LoginAsUser{
				ID:    u.ID,
				Name:  u.FullName, // preferred for logged_by.name
				Email: u.Email,    // used if Name is empty
			}, nil
		},
	},
})
```

| Field | Required when enabled | Meaning |
|---|---|---|
| `Enabled` | — | Master switch (default `false`) |
| `Roles` | yes | Role **names** that may impersonate (matched like [`GetRole`](./roles-and-permissions.md); `admin:rw` grants count as `admin`) |
| `ResolveUser` | yes | Load actor display name and confirm the target exists |

`New` returns an error if `Enabled` is true but `Roles` or `ResolveUser` is missing.

## 2. Database: `sessions.logged_by`

Add a nullable column on your sessions table (or re-run GORM `AutoMigrate` on `goauth.Session`):

```sql
-- PostgreSQL
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS logged_by varchar(64);

-- SQLite
ALTER TABLE sessions ADD COLUMN logged_by TEXT;

-- MySQL
ALTER TABLE sessions ADD COLUMN logged_by VARCHAR(64) NULL;
```

| Column | Meaning |
|---|---|
| `user_id` | The user being impersonated (effective principal) |
| `logged_by` | The admin who started the impersonation |
| `method` | `login_as` for these sessions |

See [Database setup](../getting-started/database-setup.md#the-sessions-table).

## 3. Call the endpoint

The caller must already have a **WEB session cookie** (same cookie as `UseWEBAuthorization`).

```bash
# Browser-style: HTML callback → localStorage + cookie + redirect home
curl -i -b 'cnf.id=<admin-session-id>' \
  'https://app.example.com/api/authorization/login_as?user_id=<target-uuid>'

# API / SPA: JSON body
curl -s -b 'cnf.id=<admin-session-id>' \
  -H 'Accept: application/json' \
  'https://app.example.com/api/authorization/login_as?user_id=<target-uuid>'
```

`POST` with form/JSON field `user_id` is also accepted.

### Success (JSON)

```json
{
  "type": "sign_in",
  "message": "Signed in as Bob User",
  "user": { "id": "…", "name": "Bob User", "email": "bob@example.com" },
  "tokens": {
    "access_token": "eyJ…",
    "refresh_token": "eyJ…"
  },
  "session_id": "…",
  "logged_by": { "id": "admin-uuid", "name": "Ada Admin" },
  "redirect_url": "/"
}
```

Browsers without `Accept: application/json` get the same payload embedded in the [OAuth callback page](./oauth-sign-in.md#the-callback-page), which:

1. Writes tokens under `authorization-storage` in **localStorage**
2. Relies on the **HttpOnly session cookie** set by the response
3. Redirects to `redirect_url` (`UI.DefaultRedirect`, default `/`)

## 4. JWT claims

Both access and refresh tokens carry:

```json
"logged_by": {
  "id": "admin-uuid",
  "name": "Ada Admin"
}
```

`user_id` / roles in the token are still the **target** user’s. Use `logged_by` in your UI (“Viewing as …”) and for audit logs. On refresh, goauth preserves `logged_by` from the refresh token or the session row.

## 5. Privilege rules

1. Actor must be signed in.
2. Actor roles (from the users table) must match `LoginAs.Roles`.
3. If the current session already has `logged_by` set, privilege is checked against that **original admin** so they can switch to another target without signing out first.
4. You cannot login as yourself (actor id or current session user id).
5. Impersonation does **not** re-run TOTP MFA for the target; the admin is already authenticated.

## 6. Errors

| Status | Code | When |
|---|---|---|
| 401 | `UNAUTHORIZED` | No valid session cookie |
| 403 | `LOGIN_AS_FORBIDDEN` | Actor lacks an allowed role |
| 404 | `LOGIN_AS_NOT_FOUND` | `ResolveUser` returned nil for the target |
| 400 | `LOGIN_AS_BAD_REQUEST` | Missing `user_id`, or logging in as yourself |
| 404 | — | Feature disabled (`LoginAs.Enabled` false) |

## 7. Frontend sketch

```js
// Admin tool: open impersonation in the same tab
window.location.href =
  '/api/authorization/login_as?user_id=' + encodeURIComponent(userId);

// Or fetch JSON and reuse your existing sign-in persist helper
const res = await fetch('/api/authorization/login_as?user_id=' + userId, {
  headers: { Accept: 'application/json' },
  credentials: 'include',
});
const data = await res.json();
if (data.type === 'sign_in') {
  // same persist path as OAuth callback / credentials
  GoAuthSession.persist(data);
  window.location.href = data.redirect_url || '/';
}
```

## 8. Security notes

- Restrict `LoginAs.Roles` tightly; treat this like production root access.
- Prefer HTTPS and `__Host-` / `__Secure-` cookies (see [Cookies](./cookies.md)).
- Log `logged_by` + target `user_id` in your own audit trail for support actions.
- Sign-out ends the impersonation session like any other session ([Sign-out](./sign-out.md)); the admin’s previous session is a separate row unless you reuse/expire it yourself.

Related: [Roles and permissions](./roles-and-permissions.md), [Tokens and refresh](./tokens-and-refresh.md), [Sessions](./sessions-and-redis.md).
