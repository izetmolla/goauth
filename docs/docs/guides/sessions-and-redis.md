---
title: Sessions and Redis
description: How sessions are stored, looked up and cached in Redis, and the session helper functions.
---

# Sessions and Redis

## Session lifecycle

| Event | What happens |
|---|---|
| Sign-in (`Authorize`) | Row inserted with `expires_at = now + RefreshTokenDuration` |
| Web request / refresh | Row loaded, checked for `is_deleted` and `expires_at`, user roles read |
| Sign-out | You set `is_deleted = true` (see [Sign-out](./sign-out.md)) |
| Expiry | Row stays in the table but no longer authenticates; clean up periodically |

## Reading sessions

```go
session, err := auth.GetSession(ctx, sessionID)
switch {
case errors.Is(err, goauth.ErrSessionNotFound):
	// unknown, empty id, or signed out
case errors.Is(err, goauth.ErrSessionExpired):
	// past expires_at
case err != nil:
	// database error
}
fmt.Println(session.UserID, goauth.FormatRoles(session.User.Roles))
```

Other helpers:

| Function | Returns |
|---|---|
| `auth.GetSessionID(r)` | Session id from the request's cookie, or `""` |
| `auth.GetSession(ctx, id)` | `*goauth.Session` with `User.ID` and `User.Roles` |
| `auth.GetSessionFromDB(ctx, id)` | Same, without mapping "not found" to `ErrSessionNotFound` |
| `auth.CreateSession(opts)` | Insert a row and return its id (used by `Authorize`) |
| `auth.SetSessionIDCookie(w, r, id)` | Write the session cookie |

## Enabling Redis

Web requests hit the database on every request. With Redis, the session and roles are cached:

```go
import "github.com/redis/go-redis/v9"

rdb := redis.NewClient(&redis.Options{
	Addr:     os.Getenv("REDIS_ADDR"), // "localhost:6379"
	Password: os.Getenv("REDIS_PASSWORD"),
})
if err := rdb.Ping(ctx).Err(); err != nil {
	log.Fatal(err)
}

auth, err := goauth.New(&goauth.Config{
	JWTSecret:   os.Getenv("JWT_SECRET"),
	DB:          db,
	Redis:       rdb,
	RedisPrefix: "myapp:sessions", // default "AUTHSESSIONS"
	RedisTTL:    15 * time.Minute, // default 30m
})
```

Cached values are small JSON documents:

```text
myapp:sessions:3f0c9a51-...  →  {"id":"3f0c9a51-...","user_id":"5b1c...","roles":["admin:rw"]}
```

### How lookups work with Redis

1. Read `prefix:<id>` from Redis.
2. **Hit**: still confirm in the database that the session is not signed out or expired, and read the user's current roles. If the roles changed, refresh the cache.
3. **Miss**: load the session and user from the database, then write the cache entry with `RedisTTL`.

Because step 2 always confirms liveness, a signed-out session stops working immediately, even while its cache entry exists.

:::info[Trade-off]
This design favors correctness (instant revocation, live roles) over saving database queries. If you need fewer queries, keep `AccessTokenDuration` short and protect most traffic with `UseAPIAuthorization`, which never touches the database.
:::

### Writing to the cache yourself

```go
err := auth.SetSessionToRedis(ctx, &goauth.SessionData{
	ID:     sessionID,
	UserID: userID,
	Roles:  goauth.JSONBArray{"admin:rw"},
})

data, err := auth.GetSessionFromRedis(ctx, sessionID) // *goauth.SessionData; redis.Nil when missing
```

## The `Session` model

```go
type Session struct {
	ID        string          // uuid
	UserID    string
	User      goauth.User     // loaded separately: ID + Roles (not a column)
	Type      SessionType     // "sign_in" | "oauth"
	IPAddress string
	UserAgent string
	Method    string          // provider id or WithMethod value
	Account   goauth.JSONBAny // provider Account for OAuth sign-ins
	ExpiresAt time.Time
	IsDeleted bool
	CreatedAt, UpdatedAt time.Time
	DeletedAt gorm.DeletedAt
}
```

For OAuth sign-ins, `Account` holds the provider's tokens (`access_token`, `refresh_token`, `id_token`, `expires_at`, `scope`). You can use them to call the provider's API on the user's behalf:

```go
var row struct{ Account goauth.JSONBAny }
db.Table("sessions").Select("account").Where("id = ?", sessionID).Take(&row)
graphToken, _ := row.Account["access_token"].(string)
```

:::caution
`Account` stores provider tokens in plain text. Restrict access to the sessions table, and encrypt the column if your threat model requires it.
:::

## JSON helper types

| Type | Go type | Use |
|---|---|---|
| `goauth.JSONBArray` | `[]any` | Arrays such as roles; implements `sql.Scanner` and `driver.Valuer` |
| `goauth.JSONBAny` | `map[string]any` | Objects such as `Account` and `content` |

Both scan from JSON text or bytes and have a `ToString()` method. Use them in your own GORM models:

```go
type User struct {
	ID    string            `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Email string            `gorm:"uniqueIndex"`
	Roles goauth.JSONBArray `gorm:"type:jsonb;default:'[]'"`
}
```
