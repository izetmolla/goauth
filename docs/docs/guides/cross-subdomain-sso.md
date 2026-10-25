---
title: Cross-subdomain SSO
description: Share one sign-in across example.com, manager.example.com and finance.example.com.
---

# Cross-subdomain single sign-on

Sign in once at `auth.example.com`, and be signed in on `manager.example.com`, `finance.example.com` and any other subdomain.

## How it works

All apps:

1. Share the same **database** (sessions and users tables).
2. Use the same **`JWTSecret`**, so tokens from one app validate in another.
3. Use the same **cookie names** with `Domain=.example.com`, so the browser sends the session cookie to every subdomain.

```text
            ┌──────────────────────────────┐
            │  auth.example.com            │  sign-in + OAuth callback
            │  sets cnf.id; Domain=.example.com
            └──────────────┬───────────────┘
                           │ browser sends cnf.id to every *.example.com
          ┌────────────────┴───────────────┐
          ▼                                ▼
 manager.example.com               finance.example.com
 UseWEBAuthorization               UseWEBAuthorization
 (same DB, same secret)            (same DB, same secret)
```

## Shared setup

Put the configuration in a package that every app imports:

```go
package authsetup

import (
	"os"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/google"
	"gorm.io/gorm"
)

// New builds the shared Authorization. resolveUser is defined in this package.
func New(db *gorm.DB) (*goauth.Authorization, error) {
	cookies := goauth.CrossSubdomainCookies(".example.com")
	return goauth.New(&goauth.Config{
		JWTSecret:         os.Getenv("JWT_SECRET"), // identical everywhere
		AuthURL:           "https://auth.example.com",
		SignInRedirectURL: "https://auth.example.com/sign-in",
		DB:                db,
		Cookies:           &cookies,
		CookieSessionName: "cnf.id", // identical everywhere
		Providers: []goauth.Provider{
			google.New(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")),
		},
		ResolveUser: resolveUser(db),
	})
}
```

Key points:

- **`AuthURL`** points every app at the central auth host, so all OAuth redirect URIs are on `auth.example.com`. Register only that one redirect URI at the provider.
- **`SignInRedirectURL`** is absolute, so anonymous users on `finance.example.com/reports` go to `https://auth.example.com/sign-in?redirectUrl=https%3A%2F%2Ffinance.example.com%2Freports`.
- Only `auth.example.com` needs to mount `auth.Handler()`. The other apps only use the middlewares.

## The auth app

```go
mux.Handle(goauth.DefaultBasePath+"/", auth.Handler())
mux.HandleFunc("GET /sign-in", signInPage) // validates redirectUrl against *.example.com
```

Because the callback page redirects to `redirectUrl` from `localStorage`, store the validated target there before starting sign-in (see [Protecting web pages](./protecting-web-pages.md#a-sign-in-page-that-returns-the-user)). Allow only your own subdomains:

```go
func allowedRedirect(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" &&
		(u.Host == "example.com" || strings.HasSuffix(u.Host, ".example.com"))
}
```

## The other apps

```go
mux.Handle("/", auth.UseWEBAuthorization()(app))
```

## Requirements and pitfalls

- **HTTPS everywhere.** Shared cookies are `Secure` on HTTPS, and the browser drops them on plain HTTP subdomains.
- **Same secret, same cookie names, same `RefreshTokenDuration`** on every app.
- **Not across different sites**: cookies cannot be shared between `example.com` and `example.org`. Use the token flow (`CheckSession`) for that.
- Any subdomain can read these cookies, so only share them with subdomains you control. Don't use this on a domain where users host their own content.

## Restoring a session on a new domain

A browser that has tokens in `localStorage` but no cookie for the current domain can exchange its refresh token for a session cookie with [`CheckSession`](./tokens-and-refresh.md#checksession-restore-a-web-session-from-a-refresh-token).
