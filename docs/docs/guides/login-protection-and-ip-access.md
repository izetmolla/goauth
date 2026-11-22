---
title: Login protection and IP access
description: Lock accounts after repeated wrong passwords, and allow or block client addresses with whitelist and blacklist rules.
---

# Login protection and IP access

Two optional features, both off by default and both stored in goauth-owned tables.

## Behind a proxy: set `TrustedProxies` first

Both features need the real client address. goauth reads `X-Forwarded-For` and `X-Real-IP` **only** when the request arrives from a proxy listed in `TrustedProxies`; otherwise it uses the TCP peer address. Without this rule, any client could send `X-Forwarded-For: <allowed address>` and bypass the IP rules or spread failed logins across fake addresses.

```go
goauth.New(&goauth.Config{
	// ...
	TrustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12"}, // your load balancers
})
```

`X-Forwarded-For` is read right to left, skipping trusted proxies, so a client cannot prepend a fake address either. Leave `TrustedProxies` empty when clients connect to your app directly.

## Login protection

Counts wrong passwords per email (or phone, username, or the client IP when the form has none of those) and refuses credentials sign-in for that identifier for `LockoutFor` once `MaxFailures` is reached.

```go
goauth.New(&goauth.Config{
	// ...
	LoginProtection: goauth.LoginProtectionOptions{
		Enabled:     true,
		MaxFailures: 5,                // 1 to 100, required
		LockoutFor:  15 * time.Minute, // 1 minute to 24 hours, required
	},
})

if err := auth.MigrateLoginAttempts(ctx); err != nil { // creates goauth_login_attempts
	log.Fatal(err)
}
```

- A locked sign-in answers `429` with code `LOGIN_LOCKED`.
- A successful sign-in, or a successful password reset, clears the identifier's streak.
- Failures are counted atomically, so parallel guesses all count toward the limit.
- Each row also stores the last IP, user agent and an optional device id (`X-Device-MAC`, `X-Client-MAC` or `X-Device-Id` header, or a `mac` form field). Browsers cannot read a real MAC address; treat this as a client-supplied hint.

:::caution[Lockouts can be triggered by anyone]
Anyone who knows an email can lock that account by entering wrong passwords. Keep `LockoutFor` short, and let users recover with a password reset, which clears the lockout.
:::

## IP access rules

Whitelist and blacklist entries (single addresses or CIDR ranges, IPv4 or IPv6) checked on every request to `auth.Handler()`:

- a blacklisted address is always refused (`403`, code `IP_FORBIDDEN`);
- when at least one whitelist entry is enabled, only matching addresses are allowed.

```go
goauth.New(&goauth.Config{
	// ...
	IPAccess: goauth.IPAccessOptions{
		Enabled:       true,
		SeedWhitelist: []string{"203.0.113.0/24"}, // inserted by MigrateIPAccess when missing
		SeedBlacklist: []string{"198.51.100.7"},
		CacheTTL:      30 * time.Second,           // default; negative disables the cache
	},
})

if err := auth.MigrateIPAccess(ctx); err != nil { // creates goauth_ip_access_rules
	log.Fatal(err)
}
```

Manage rules at runtime:

```go
entry, err := auth.AddWhitelistIP(ctx, "192.0.2.10", "office")
entry, err = auth.UpdateWhitelistIP(ctx, entry.ID, goauth.IPEntryUpdate{Enabled: &disabled})
err = auth.RemoveWhitelistIP(ctx, entry.ID)
rules, err := auth.ListBlacklistIPs(ctx)
```

Enabled rules are kept in memory for `CacheTTL`, so checking a request costs no database query. Changes made through these functions apply immediately on that instance; changes from other instances or direct SQL apply within `CacheTTL`.

The rules protect goauth's own endpoints. Your other routes are not filtered.

## Table names

| Feature | Default table | Exact name |
|---|---|---|
| Login protection | `goauth_login_attempts` | `LoginProtection.TableName` |
| IP access | `goauth_ip_access_rules` | `IPAccess.TableName` |

Both follow the [table prefix](./configuration.md#table-names).
