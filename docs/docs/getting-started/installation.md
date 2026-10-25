---
title: Installation
description: Add goauth to a Go module and pick a database driver.
---

# Installation

## Add the module

```bash
go get github.com/izetmolla/goauth@latest
```

goauth needs **Go 1.27 or newer**. Check your version with:

```bash
go version
```

## Add a database driver

goauth stores sessions through [GORM](https://gorm.io), so you also need a GORM driver for your database.

PostgreSQL (recommended):

```bash
go get gorm.io/driver/postgres
```

SQLite without cgo (handy for local development and tests):

```bash
go get github.com/glebarez/sqlite
```

MySQL:

```bash
go get gorm.io/driver/mysql
```

## Optional packages

Redis session cache:

```bash
go get github.com/redis/go-redis/v9
```

Framework adapters are only needed when you use that framework:

| Framework | Package | Adapter used in these docs |
|---|---|---|
| net/http, Chi | none | handlers and middlewares are used directly |
| Fiber v3 | `github.com/gofiber/fiber/v3` | `fiber/v3/middleware/adaptor` |
| Echo v5 | `github.com/labstack/echo/v5` | `echo.WrapHandler`, `echo.WrapMiddleware` |
| Gin | `github.com/gin-gonic/gin` | `gin.WrapH` plus a 15-line middleware wrapper |

## Package layout

| Import path | What it contains |
|---|---|
| `github.com/izetmolla/goauth` | Core: `New`, `Config`, handlers, middlewares, tokens, sessions, roles, cookies, password hashing |
| `github.com/izetmolla/goauth/providers/google` | Google OpenID Connect provider |
| `github.com/izetmolla/goauth/providers/azuread` | Microsoft Azure AD / Entra ID provider |
| `github.com/izetmolla/goauth/providers/credentials` | Credentials (username/password) provider definition |
| `github.com/izetmolla/goauth/providers/ldap` | LDAP / Active Directory client for password verification |

## Versioning

goauth follows [semantic versioning](https://semver.org). Pin a release in `go.mod`:

```bash
go get github.com/izetmolla/goauth@v1.1.0
```

All releases are listed on the [GitHub tags page](https://github.com/izetmolla/goauth/tags).

Next: [Quick start](./quick-start.md).
