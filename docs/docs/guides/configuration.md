---
title: Configuration
description: Every goauth.Config field, its default, and how to load settings from the environment.
---

# Configuration

## Minimal configuration

Only two fields are required:

```go
auth, err := goauth.New(&goauth.Config{
	JWTSecret: os.Getenv("JWT_SECRET"),
	DB:        db,
})
```

`New` returns an error if `JWTSecret` is empty or `DB` is nil. Every other field falls back to a default.

`New` also rejects configurations that would only fail later: an invalid or non-positive duration, an unknown `SigningMethod`, an `AuthURL` that is not `http(s)://host`, a nil provider, an empty or duplicate provider id, and an OAuth provider without a `Profile` function.

## All fields

```go
auth, err := goauth.New(&goauth.Config{
	// --- Security --------------------------------------------------------
	JWTSecret:     os.Getenv("JWT_SECRET"), // required: HMAC key for tokens and signed cookies
	SigningMethod: "HS256",                 // HS256 (default) | HS384 | HS512

	// --- URLs ------------------------------------------------------------
	AuthURL:           "https://app.example.com", // public origin used in OAuth redirect URIs
	SignInRedirectURL: "/sign-in",                // where UseWEBAuthorization sends anonymous users

	// --- Token lifetimes -------------------------------------------------
	AccessTokenDuration:  "15m", // default "60s"
	RefreshTokenDuration: "30d", // default "1y"; also the session and cookie lifetime

	// --- Storage ---------------------------------------------------------
	DB:               db,         // required *gorm.DB
	UserTableName:    "users",    // default "users"
	SessionTableName: "sessions", // default "sessions"
	TablePrefix:      "goauth_",  // prefix of the tables goauth owns; default goauth.DefaultTablePrefix

	Redis:       redisClient,      // optional *redis.Client session cache
	RedisPrefix: "AUTHSESSIONS",   // default "AUTHSESSIONS"
	RedisTTL:    30 * time.Minute, // default 30m

	// --- Cookies ---------------------------------------------------------
	CookieSessionName: "cnf.id",                 // default "cnf.id"
	Cookies:           &goauth.CookieOptions{}, // per-cookie overrides

	// --- Sign-in ---------------------------------------------------------
	Providers:         []goauth.Provider{ /* ... */ },
	ResolveUser:       resolveUser,       // required for OAuth providers
	OnProviderConnect: onProviderConnect, // optional, see "Provider connect"

	// --- Optional features (all off by default) --------------------------
	Verification: goauth.VerificationOptions{ /* password reset, email confirm, OTP */ },
	MFA:          goauth.MFAOptions{TOTP: goauth.TOTPOptions{Enabled: false}},
	LoginAs:      goauth.LoginAsOptions{Enabled: false},
})
```

| Field | Default | Notes |
|---|---|---|
| `JWTSecret` | **required** | Use at least 32 random bytes. Rotating it invalidates every token and signed cookie. Also derives keys for verification hashes and TOTP secret encryption. |
| `SigningMethod` | `HS256` | `HS256`, `HS384` or `HS512` (case-insensitive). Any other value makes `New` return an error. Tokens are only accepted when signed with this exact algorithm and carrying an `exp` claim. |
| `AuthURL` | from request | See [AuthURL](#authurl). |
| `SignInRedirectURL` | `/sign-in` | Can be absolute, for example `https://auth.example.com/sign-in`. |
| `AccessTokenDuration` | `60s` | See [Duration format](#duration-format). |
| `RefreshTokenDuration` | `1y` | Also used for `sessions.expires_at` and the session cookie's `Max-Age`. |
| `DB` | **required** | Any GORM database. |
| `UserTableName` | `users` | Must have `id` and `roles` columns. |
| `SessionTableName` | `sessions` | See [Database setup](../getting-started/database-setup.md). |
| `TablePrefix` | `goauth_` | Prefix of the tables goauth owns. See [Table names](#table-names). |
| `Redis` | none | See [Sessions and Redis](./sessions-and-redis.md). |
| `RedisPrefix` | `AUTHSESSIONS` | Keys look like `AUTHSESSIONS:<session id>`. |
| `RedisTTL` | `30m` | How long a cached session lives in Redis. |
| `CookieSessionName` | `cnf.id` | Name of the web session cookie. |
| `Cookies` | secure defaults | See [Cookies](./cookies.md). |
| `Providers` | none | See [Providers](../providers/overview.md). |
| `ResolveUser` | none | Required before any OAuth sign-in can complete. |
| `OnProviderConnect` | none | See [Provider connect](./provider-connect.md). |
| `Endpoints` | sign-in on, sign-up off | Switch built-in API endpoints on/off. See [Built-in pages](./sign-in-page.md#switching-parts-on-and-off). |
| `UI` | all pages off | Turn pages on (`EnableAllUI` or one by one), set their paths (`SignInEndpoint`, …) and branding for the pages and emails. |
| `Verification` | all off | Password reset, email confirmation, one-time codes. See [verification](./verification.md). |
| `MFA` | TOTP off | Authenticator-app MFA. See [Authenticator MFA](./mfa-totp.md). |
| `LoginAs` | off | Admin impersonation (`/login_as`). See [Login as](./login-as.md). |
| `KeepRefreshTokenServerSide` | `false` | Keep the refresh token out of the OAuth callback page; web clients refresh with the session cookie. See [Tokens and refresh](./tokens-and-refresh.md#keeping-the-refresh-token-out-of-the-browser). |

## Table names

goauth creates and owns these tables (each only when its feature is on). Their names start with a prefix, `goauth_` by default, so they stay apart from your own tables:

| Table | Default name | Created by | Exact name |
|---|---|---|---|
| Verification codes and links | `goauth_verification_tokens` | `auth.MigrateVerificationTokens` | `Verification.TableName` |
| TOTP factors | `goauth_totp` | `auth.MigrateTOTP` | `MFA.TOTP.TableName` |
| Login attempts | `goauth_login_attempts` | `auth.MigrateLoginAttempts` | `LoginProtection.TableName` |
| IP access rules | `goauth_ip_access_rules` | `auth.MigrateIPAccess` | `IPAccess.TableName` |

Change the prefix for every instance in your package's `init` function, or for one instance with `Config.TablePrefix`:

```go
func init() {
	goauth.DefaultTablePrefix = "auth_" // auth_verification_tokens, auth_totp, ...
}

auth, err := goauth.New(&goauth.Config{
	TablePrefix: "billing_auth_", // this instance only
	// ...
})
```

Set `goauth.DefaultTablePrefix = ""` for unprefixed names. An explicit `TableName` is always used as is. The users and sessions tables are not prefixed: set them with `UserTableName` and `SessionTableName`.

## Duration format

`AccessTokenDuration` and `RefreshTokenDuration` are strings with one integer and one unit. They are parsed once in `New`, which returns an error for an invalid value, so a typo fails at startup instead of at the first sign-in:

| Unit | Meaning | Example |
|---|---|---|
| `s` | seconds | `"60s"` |
| `m` | minutes | `"15m"` |
| `h` | hours | `"12h"` |
| `d` | days | `"7d"` |
| `w` | weeks | `"2w"` |
| `mo` | 30 days | `"6mo"` |
| `y` | 365 days | `"1y"` |

Compound values such as `"1h30m"` are not supported; use `"90m"`. The same parser is exported as `goauth.ParseCustomDuration(input, fallback)`.

## AuthURL

`AuthURL` is the public origin of your app, used to build OAuth `redirect_uri` values and to decide whether cookies are `Secure`.

- `"https://app.example.com"` → callback is `https://app.example.com/api/authorization/provider/{id}/callback`.
- `"app.example.com"` (no scheme) → `https://` is assumed.
- Any path or trailing slash is dropped; only scheme and host are kept.
- Empty → derived per request from `X-Forwarded-Host`/`Host` and `X-Forwarded-Proto`/TLS.

:::warning[Set AuthURL in production]
When `AuthURL` is empty, goauth trusts the `X-Forwarded-Host` and `X-Forwarded-Proto` headers. Only leave it empty behind a reverse proxy that overwrites those headers.
:::

## Loading from the environment

```go
func loadConfig(db *gorm.DB, rdb *redis.Client) *goauth.Config {
	return &goauth.Config{
		JWTSecret:            mustEnv("JWT_SECRET"),
		AuthURL:              os.Getenv("AUTH_URL"),
		AccessTokenDuration:  os.Getenv("ACCESS_TOKEN_TTL"),  // "" → default
		RefreshTokenDuration: os.Getenv("REFRESH_TOKEN_TTL"), // "" → default
		SignInRedirectURL:    os.Getenv("SIGN_IN_URL"),
		DB:                   db,
		Redis:                rdb,
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s is required", key)
	}
	return v
}
```

Empty strings are safe: they fall back to defaults.

## Functional options (`ConfigFunc`)

`New` accepts optional `ConfigFunc` values, applied to a copy of the config before validation. Use them to share a base config and adjust it per environment:

```go
func withTestDurations(cfg *goauth.Config) {
	cfg.AccessTokenDuration = "5s"
	cfg.RefreshTokenDuration = "1m"
}

auth, err := goauth.New(baseConfig, withTestDurations)
```

The `*Config` you pass is never modified.

## Setters after `New`

`Authorization` also has chainable setters, handy in tests:

```go
auth.WithAuthURL("http://localhost:3000").
	WithDB(testDB).
	WithRedis(nil).
	WithCookieSessionName("test.sid")
```

Available setters: `WithJWTSecret`, `WithAuthURL`, `WithDB`, `WithRedis`, `WithRedisPrefix`, `WithRedisTTL`, `WithCookieSessionName`, `WithResolveUser`. Empty or nil arguments are ignored.

:::caution
Setters change shared state without locking. Call them only during startup, before the server handles requests.
:::

## Package-level defaults

Defaults are exported variables, so tests can change them without forking:

```go
goauth.DefaultAccessTokenDuration  // "60s"
goauth.DefaultRefreshTokenDuration // "1y"
goauth.DefaultSigningMethodHMAC    // "HS256"
goauth.DefaultRedisTTL             // 30 * time.Minute
goauth.DefaultRedisPrefix          // "AUTHSESSIONS"
goauth.DefaultCookieSessionName    // "cnf.id"
goauth.DefaultSignInRedirectURL    // "/sign-in"
goauth.DefaultTablePrefix          // "goauth_"
goauth.DefaultUserTableName        // "users"
goauth.DefaultSessionTableName     // "sessions"
goauth.DefaultBasePath             // "/api/authorization"
```
