---
title: Database setup
description: The users and sessions tables goauth needs, for PostgreSQL, SQLite and MySQL.
---

# Database setup

goauth reads and writes two tables through GORM:

| Table | Default name | Owned by | goauth uses |
|---|---|---|---|
| Users | `users` | **you** | reads `id` and `roles` |
| Sessions | `sessions` | goauth | creates, reads and checks rows |

Change the names with `Config.UserTableName` and `Config.SessionTableName`.

## The users table

goauth never creates or updates users. Your app does that, usually inside [`ResolveUser`](../guides/oauth-sign-in.md#step-2-write-resolveuser). goauth only needs two columns:

| Column | Type | Meaning |
|---|---|---|
| `id` | UUID or text | The user id written into tokens and session rows |
| `roles` | JSON array | Role grants such as `["admin:rw", "hr:r"]`. See [Roles and permissions](../guides/roles-and-permissions.md) |

Add any other columns you need (`email`, `name`, `password_hash`, ...).

:::info[Roles are read live]
Whenever goauth issues or refreshes a token, it re-reads `roles` from this table. Changing a user's roles takes effect at the next token refresh, without signing them out.
:::

## The sessions table

Every sign-in creates one row. Its columns match the `goauth.Session` struct:

| Column | Type | Meaning |
|---|---|---|
| `id` | UUID, primary key | Session id, stored in the session cookie and in the refresh token |
| `user_id` | UUID | Owner of the session |
| `type` | varchar | `sign_in` (default) or `oauth` |
| `ip_address` | varchar(50) | Client IP at sign-in |
| `user_agent` | varchar(255) | Client user agent at sign-in |
| `method` | varchar(50) | Provider id used to sign in (`google`, `credentials`, ...) |
| `account` | JSON | Provider account and tokens (`goauth.Account`) for OAuth sign-ins |
| `expires_at` | timestamp | When the refresh token expires |
| `is_deleted` | boolean | `true` once the session is signed out |
| `created_at`, `updated_at`, `deleted_at` | timestamp | GORM bookkeeping |

A session authenticates only while `is_deleted = false` and `expires_at` is in the future.

## PostgreSQL

PostgreSQL is the primary target: the `Session` model uses `uuid`, `jsonb` and `gen_random_uuid()`. You can let GORM create the sessions table:

```go
import (
	"github.com/izetmolla/goauth"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

db, err := gorm.Open(postgres.Open(os.Getenv("DATABASE_URL")), &gorm.Config{})
if err != nil {
	log.Fatal(err)
}
if err := db.Table("sessions").AutoMigrate(&goauth.Session{}); err != nil {
	log.Fatal(err)
}
```

Or write the SQL yourself, for example in a migration tool:

```sql
CREATE TABLE IF NOT EXISTS users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email         text UNIQUE NOT NULL,
    name          text,
    password_hash text,
    roles         jsonb NOT NULL DEFAULT '[]',
    content       jsonb NOT NULL DEFAULT '{}',
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid REFERENCES users(id) ON DELETE CASCADE,
    type       varchar(255) DEFAULT 'sign_in',
    ip_address varchar(50),
    user_agent varchar(255),
    method     varchar(50) DEFAULT 'credentials',
    account    jsonb,
    expires_at timestamptz,
    is_deleted boolean DEFAULT false,
    created_at timestamptz,
    updated_at timestamptz,
    deleted_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id    ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_deleted_at ON sessions (deleted_at);
```

## SQLite

SQLite has no `uuid`/`jsonb` types, so create the tables with plain SQL. Session ids are generated in Go (`Session.BeforeCreate`), so no database default is needed.

```sql
CREATE TABLE IF NOT EXISTS users (
    id      TEXT PRIMARY KEY,
    email   TEXT UNIQUE,
    roles   TEXT DEFAULT '[]',
    content TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT,
    type       TEXT DEFAULT 'sign_in',
    ip_address TEXT,
    user_agent TEXT,
    method     TEXT DEFAULT 'credentials',
    account    TEXT,
    expires_at DATETIME,
    is_deleted NUMERIC DEFAULT 0,
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME
);
```

## MySQL

```sql
CREATE TABLE IF NOT EXISTS users (
    id      CHAR(36) PRIMARY KEY,
    email   VARCHAR(255) UNIQUE,
    roles   JSON NOT NULL,
    content JSON
);

CREATE TABLE IF NOT EXISTS sessions (
    id         CHAR(36) PRIMARY KEY,
    user_id    CHAR(36),
    type       VARCHAR(255) DEFAULT 'sign_in',
    ip_address VARCHAR(50),
    user_agent VARCHAR(255),
    method     VARCHAR(50) DEFAULT 'credentials',
    account    JSON,
    expires_at DATETIME(3),
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at DATETIME(3),
    updated_at DATETIME(3),
    deleted_at DATETIME(3),
    INDEX idx_sessions_user_id (user_id),
    INDEX idx_sessions_deleted_at (deleted_at)
);
```

## Seeding a first admin

```sql
-- PostgreSQL
INSERT INTO users (email, roles) VALUES ('admin@example.com', '["admin:rw"]');
```

## Cleaning up old sessions

Expired and signed-out rows are never deleted automatically. Run a periodic job:

```sql
DELETE FROM sessions
WHERE is_deleted = true
   OR expires_at < now() - interval '30 days';
```

Next: [Core concepts](./core-concepts.md).
