---
slug: /intro
sidebar_position: 1
title: Introduction
description: goauth is a framework-agnostic authentication and authorization module for Go, built on net/http.
---

# goauth

**goauth** is an authentication and authorization module for Go. It is built entirely on `net/http`, so it works with every Go web framework.

It gives you:

- **Sign-in** with OAuth 2.0 / OpenID Connect (Google, Azure AD / Entra ID, or any custom provider), plus building blocks for password and LDAP / Active Directory sign-in.
- **Tokens**: a short-lived JWT access token and a long-lived refresh token for every session.
- **Sessions** stored in your SQL database through [GORM](https://gorm.io), with an optional [Redis](https://redis.io) cache.
- **Two protection modes**: Bearer JWT for APIs, and a session cookie (with redirect to your sign-in page) for server-rendered pages.
- **Role-based access control** with read/write grants such as `admin:rw` and `hr:r`.
- **Security defaults**: `__Host-`/`__Secure-` cookie prefixes, PKCE, `state` and `nonce` checks, signed CSRF cookies, PBKDF2-SHA256 password hashing and cross-subdomain single sign-on.

```bash
go get github.com/izetmolla/goauth
```

## Why goauth

| | |
|---|---|
| **No framework lock-in** | Handlers are `http.Handler`, middlewares are `func(http.Handler) http.Handler`. See [Frameworks](./frameworks/net-http.mdx). |
| **You own the users** | goauth never creates users. A single `ResolveUser` callback maps a provider profile to a row in *your* database. |
| **Auth.js-compatible** | Endpoint shapes, cookie names and the `/providers` JSON match [Auth.js](https://authjs.dev), so existing frontends feel at home. |
| **Small surface** | One `goauth.New(...)`, one `auth.Handler()`, two middlewares. |

## How the docs are organized

The docs go from simple to advanced:

1. **[Getting started](./getting-started/installation.md)**: install, run a working app in five minutes, create the database tables and learn the core ideas.
2. **[Guides](./guides/configuration.md)**: one topic per page: configuration, endpoints, OAuth, protecting routes, roles, tokens, password sign-in, sign-out, Redis, cookies, account linking and single sign-on.
3. **[Providers](./providers/overview.md)**: Google, Azure AD, credentials, LDAP and writing your own OAuth provider.
4. **[Custom providers](./custom-providers/overview.md)**: add any OAuth 2.0 / OpenID Connect provider, step by step, with a reusable package and tests.
5. **[Frameworks](./frameworks/net-http.mdx)**: complete apps for net/http, Fiber, Echo, Gin and Chi.
6. **[pkg.go.dev](https://pkg.go.dev/github.com/izetmolla/goauth)**: the full Go API reference.

:::tip[Search]
Press **Ctrl + K** (**⌘ + K** on macOS) anywhere on this site to search the docs. The search index is built into the site, so it works offline and needs no external service.
:::

## Requirements

- **Go 1.27** or newer (the version in the module's `go.mod`).
- A **SQL database** supported by GORM. PostgreSQL is the primary target; SQLite and MySQL work with the schemas in [Database setup](./getting-started/database-setup.md).
- Optional: **Redis** for session caching.

## Author

goauth is created and maintained by **Izet Molla**.

- GitHub: [github.com/izetmolla](https://github.com/izetmolla)
- Source code: [github.com/izetmolla/goauth](https://github.com/izetmolla/goauth)
- Go package docs: [pkg.go.dev/github.com/izetmolla/goauth](https://pkg.go.dev/github.com/izetmolla/goauth)

Bug reports and pull requests are welcome on GitHub.
