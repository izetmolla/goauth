# Changelog

## Unreleased

### Added

- **`Config.AutoMigrate`** runs `auth.Migrate` inside `New`: creates/updates the sessions table and every enabled feature table (verification tokens, TOTP, login attempts, IP access). Off by default. Also adds `Migrate`, `MigrateSessions`, and `HasMigrated`. The users table is never migrated.
- **GORM `TableName()`** on `VerificationToken`, `TotpFactor`, `LoginAttempt`, and `IPEntry` defaults to the `goauth_`-prefixed names.
- **`Session` GORM tags are portable** (`size` / `text` instead of PostgreSQL-only `uuid` / `jsonb` / `gen_random_uuid()`), so `MigrateSessions` works on MySQL and SQLite too. Existing databases keep their column types; new AutoMigrate tables get portable types. Prefer your own SQL for native `uuid`/`jsonb`.

## v1.9.0

### Added

- **Login protection** (`Config.LoginProtection`): locks an identifier after `MaxFailures` wrong passwords for `LockoutFor`. Table `goauth_login_attempts` (`auth.MigrateLoginAttempts`).
- **IP access rules** (`Config.IPAccess`): whitelist and blacklist entries enforced on every goauth request, with runtime CRUD (`AddWhitelistIP`, `ListBlacklistIPs`, ...). Table `goauth_ip_access_rules` (`auth.MigrateIPAccess`). Enabled rules are cached for `IPAccess.CacheTTL` (default 30s), so a request costs no database query.
- `POST {base}/password/check` (`auth.HandleResetCheck`): checks a reset link or code without consuming it.
- `Config.TrustedProxies`: the proxies whose `X-Forwarded-For` / `X-Real-IP` headers are believed by IP access and login protection. Without it the TCP peer address is used, so clients cannot spoof their address.
- A successful password reset signs the user in and clears their login lockout.

### Notes

- Login failures are counted with atomic database updates, so parallel wrong passwords all count.
- Stored user agents and device ids are truncated on a character boundary, so writes never fail on invalid UTF-8.

## v1.8.0

### Changed

- **Tables goauth owns are prefixed.** `DefaultTablePrefix` (`"goauth_"`) and the new `Config.TablePrefix` prefix the default table names, so the verification table is now `goauth_verification_tokens` (was `verification_tokens`). The TOTP table keeps its name, `goauth_totp`. Change the prefix in your package's `init` function or per instance; an explicit `Verification.TableName` or `MFA.TOTP.TableName` is still used as is.

### Upgrading

If you use verification codes (password reset, email confirmation or one-time-code sign-in), either rename the table:

```sql
ALTER TABLE verification_tokens RENAME TO goauth_verification_tokens;
```

or keep the old name with `Verification.TableName: "verification_tokens"`.

## v1.7.0

### Security

- **MFA challenge tokens are encrypted.** After an OAuth sign-in, the `mfa_token` carried the provider's access, refresh and ID tokens readable by the browser (it was signed, not encrypted). It is now sealed with AES-256-GCM under a key derived from `JWTSecret`. Challenges issued by older versions are rejected; users simply sign in again.
- **TOTP codes are single-use.** A valid authenticator code could be submitted again while it was still valid (about 90 seconds with the default skew). Each accepted time step is now remembered per user (RFC 6238 section 5.2), in memory per app instance like the attempt limit.
- **The OIDC nonce is checked.** With `CheckNonce`, the ID token returned by the token endpoint must carry the nonce that was sent.
- **Login-as CSRF:** a `?flow=token` query parameter no longer skips the CSRF check on `POST {base}/login_as`; only the `X-Auth-Flow: token` header does. `GET` is also refused for `Sec-Fetch-Site: same-site` (sibling subdomains), not only `cross-site`.
- **GitHub uses only verified emails.** When the profile has no public email, the provider used the primary address, or else the first one, even if GitHub reported it unverified. It now uses only verified addresses and sets `email_verified`.
- **Provider API calls have a timeout.** GitHub, Todoist and VK used `http.DefaultClient`, which never times out, and read responses without a size limit. VK also put the access token into the URL unescaped.
- `CheckPassword` rejects stored hashes with out-of-range parameters instead of running unbounded work.

### Fixed

- An OAuth `Profile` function returning `(nil, nil)` crashed the callback; it now shows "Profile mapping returned no user".
- Token responses that report an error with status 200 (GitHub does this), or that carry no `access_token`, are rejected with a clear message.
- `Authorize` signs the tokens before inserting the session, so a signing failure no longer leaves an orphan session row.
- `ParseCustomDuration` rejects zero and values that overflow `time.Duration`.
- A missing PKCE cookie on the callback reports "Missing PKCE verifier" instead of a confusing provider error.
- `AuthorizationParams` keep every value of a multi-valued parameter.
- `FormatUser` no longer lets `User.User` override `id` and `roles`.
- The sign-in redirect built by `UseWEBAuthorization` uses `AuthURL` as the origin when set, and handles a `SignInRedirectURL` that already has a query string.
- The `With*` setters no longer panic on a nil `*Authorization`.
- The example modules' `go.mod` files were missing indirect dependencies.

### Added

- `POST {base}/signout` (`auth.HandleSignOut`), on by default (`Endpoints.DisableSignOut` turns it off), and `auth.SignOut(w, r)`: revoke the session named by the cookie or a refresh token and expire the cookie.
- `auth.RevokeSession(ctx, id)` and `auth.RevokeUserSessions(ctx, userID)`.
- `goauth.AuthDataFromContext`. `UseWEBAuthorization` stores the principal on the request context, so `GetAuthDataWEB` no longer queries the session a second time.
- Doc comments on every exported identifier, enforced by golangci-lint.

### Changed

- `New` also rejects an `AuthURL` that is not `http(s)://host`, a nil provider, an empty or duplicate provider id, and an `OAuthProvider` without `Profile`.
- The unused `callbackUrl` and token-flow cookies are no longer set by the OAuth start endpoint.
- The shared helpers moved from `providers/internal/common` to `internal/common`, so the core package uses them too (the duplicated `asString` helper is gone).
- Modernized with `go fix` (`strings.SplitSeq`, `maps.Copy`, `errors.AsType`, `for range n`).

### Upgrading from v1.6

1. If `goauth.New` now returns an error, fix the reported setting.
2. Replace hand-written sign-out handlers with `POST /api/authorization/signout` or `auth.SignOut`; if you already have a route at that path, set `Endpoints.DisableSignOut`.
3. If a custom OIDC provider enables `CheckNonce` but its ID tokens omit the nonce, remove `CheckNonce` from that provider.
