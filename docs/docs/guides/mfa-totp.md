---
title: Authenticator MFA (TOTP)
description: Enable Google / Microsoft Authenticator–style TOTP for every sign-in path, with per-user enroll and disable stored in GORM.
---

# Authenticator MFA (TOTP)

goauth can require a time-based one-time password (TOTP) from apps such as **Google Authenticator** or **Microsoft Authenticator** after the first factor succeeds (password, OAuth, email OTP, or [passkey](../providers/passkey.md)).

TOTP is **off by default**. When `MFA.TOTP.Enabled` is true:

1. Users enroll while signed in (`/mfa/totp/enroll/*`).
2. Once a user’s factor is `enabled` in the database, **every** completed sign-in stops with `MFA_REQUIRED` until they submit a valid code (or backup code) to `/mfa/totp/verify`.

This is not the same as [email one-time-code sign-in](./verification.md) (passwordless email codes) or [passkeys](../providers/passkey.md) (WebAuthn).

## 1. Enable and migrate

```go
auth, err := goauth.New(&goauth.Config{
	JWTSecret: os.Getenv("JWT_SECRET"),
	DB:        db,
	UI:        goauth.UIOptions{AppName: "My App"},
	Providers: []goauth.Provider{ /* ... */ },
	MFA: goauth.MFAOptions{
		TOTP: goauth.TOTPOptions{
			Enabled: true,
			Issuer:  "My App", // shown in Authenticator apps
		},
	},
})
if err != nil {
	log.Fatal(err)
}
if err := auth.MigrateTOTP(ctx); err != nil {
	log.Fatal(err)
}
```

`MigrateTOTP` creates the TOTP table (default name `goauth_totp`: the [table prefix](./configuration.md#table-names) followed by `totp`). Secrets are encrypted with a key derived from `JWTSecret`; backup codes are stored only as keyed hashes.

### Manual SQL (optional)

```sql
-- PostgreSQL
CREATE TABLE IF NOT EXISTS goauth_totp (
    user_id       varchar(64) PRIMARY KEY,
    secret_enc    bytea NOT NULL,
    enabled       boolean NOT NULL DEFAULT false,
    backup_hashes text,
    confirmed_at  timestamptz,
    disabled_at   timestamptz,
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL
);
```

## 2. Enroll (signed-in user)

The user must already have a session cookie.

| Method | Path | Body |
|---|---|---|
| `GET` | `{base}/mfa/totp/status` | — |
| `POST` | `{base}/mfa/totp/enroll/begin` | optional `account` / `email` for the otpauth label |
| `POST` | `{base}/mfa/totp/enroll/confirm` | `code` from the authenticator app |
| `POST` | `{base}/mfa/totp/disable` | `code` (TOTP or backup) |

Browser POSTs need the usual CSRF cookie + `csrfToken` field (unless `X-Auth-Flow: token`). See [Credentials sign-in](./credentials-login.md) for the CSRF pattern.

**Status**

```json
{ "enabled": false, "confirmed": false }
```

**Begin** returns:

```json
{
  "secret": "BASE32…",
  "otpauth_url": "otpauth://totp/My%20App:user@example.com?secret=…&issuer=My%20App",
  "issuer": "My App",
  "account": "user@example.com"
}
```

Show a QR code from `otpauth_url` (any QR library), then **confirm** with the first 6-digit code:

```json
{
  "enabled": true,
  "backup_codes": ["ABCD2345", "…"],
  "message": "Authenticator MFA enabled. Store these backup codes somewhere safe."
}
```

Show backup codes **once**. They can later be used on `/mfa/totp/verify` or `/mfa/totp/disable` instead of the app code (each code is single-use).

**Disable** sets `enabled=false` after a valid code. Sign-in then skips MFA until the user enrolls again.

## 3. Sign-in challenge

When MFA is required, goauth does **not** create a session. This applies to credentials, OAuth (`completeSignIn`), email OTP, and passkey login finish.

JSON clients get:

```json
{
  "code": "MFA_REQUIRED",
  "message": "Authenticator code required",
  "mfa": {
    "methods": ["totp"],
    "token": "…",
    "expires": "…"
  },
  "user": { "id": "…" }
}
```

Complete sign-in:

```http
POST {base}/mfa/totp/verify
Content-Type: application/json
X-Auth-Flow: token

{"mfa_token":"…","code":"123456"}
```

Success looks like a normal `sign_in` payload (tokens / session cookie / callback page).

The `mfa.token` is opaque: it is encrypted and authenticated with a key derived from `JWTSecret`, because after an OAuth sign-in it carries the provider's tokens until the second factor is done. It expires after 5 minutes. Each authenticator code is accepted only once (RFC 6238), so a code seen over someone's shoulder cannot be replayed while it is still valid. Like the attempt limit, this is tracked in memory per app instance.

### Browser / OAuth callback

When the HTML callback receives `code: "MFA_REQUIRED"`:

- It stores `{ token, methods, user }` in `sessionStorage` under `goauth.mfa`
- If opened as a popup, it `postMessage`s `{ type: 'authorization-mfa-required', mfa, user }` to the opener and closes
- Otherwise it shows a short message so your SPA can collect the code and call `/mfa/totp/verify`

```js
window.addEventListener('message', async (ev) => {
  if (ev.origin !== window.location.origin) return;
  if (ev.data?.type !== 'authorization-mfa-required') return;
  const code = prompt('Authenticator code');
  const res = await fetch('/api/authorization/mfa/totp/verify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-Auth-Flow': 'token',
    },
    body: JSON.stringify({ mfa_token: ev.data.mfa.token, code }),
  });
  const data = await res.json();
  // persist tokens / redirect like a normal sign-in
});
```

## 4. Enable / disable summary

| Level | Behavior |
|---|---|
| `MFA.TOTP.Enabled == false` (default) | No MFA routes; all sign-ins unchanged |
| Feature on, user not enrolled / `enabled=false` | Sign-in unchanged; user may enroll |
| Feature on, user `enabled=true` | All sign-in paths challenge for TOTP before a session |

[Login as](./login-as.md) impersonation does **not** re-challenge TOTP for the target user (the admin is already authenticated).

## 5. Options

| Field | Default | Notes |
|---|---|---|
| `Enabled` | `false` | Master switch |
| `Issuer` | `UI.AppName` or `"App"` | Label in authenticator apps |
| `TableName` | `goauth_totp` | GORM table name |
| `Digits` | `6` | `6` or `8` |
| `Period` | `30` | Seconds per code |
| `Skew` | `1` | Adjacent time steps accepted |

## 6. Errors

| Code | When |
|---|---|
| `MFA_REQUIRED` | First factor OK; need TOTP (HTTP 401 on JSON sign-in) |
| `MFA_INVALID` | Wrong or expired code / `mfa_token` |
| `MFA_ALREADY_ENABLED` | Enroll begin/confirm while already enabled |
| `MFA_NOT_ENABLED` | Disable when no factor is active |
| `UNAUTHORIZED` | Enroll/status without a session |

Related: [Verification (email OTP)](./verification.md), [Passkeys](../providers/passkey.md), [Endpoints](./endpoints.md).
