# goauth examples

Each subdirectory is a **self-contained, runnable Go module** showing how to mount goauth on a specific web framework. They all expose the exact same application so you can diff them side by side — the only thing that changes is the adapter layer between `net/http` and the framework.

| Example | Framework | README |
|---------|-----------|--------|
| [`fiber/`](fiber) | [Fiber v3](https://gofiber.io) (fasthttp-based) | [fiber/README.md](fiber/README.md) |
| [`gin/`](gin) | [Gin](https://gin-gonic.com) | [gin/README.md](gin/README.md) |
| [`echo/`](echo) | [Echo v5](https://echo.labstack.com) | [echo/README.md](echo/README.md) |

## What every example implements

| Route | Protection | Shows |
|-------|-----------|-------|
| `ANY /api/authorization/*` | — | Mounting **all** goauth endpoints (`/providers`, `/provider/{id}`, `/provider/{id}/callback`) with one adapter call around `auth.Handler()` |
| `POST /api/token/refresh` | — | The `HandleRefreshToken` middleware (activates on the `cft` header, falls through otherwise) |
| `GET /api/profile` | Bearer JWT | Protecting a **net/http handler** with `UseAPIAuthorization` and reading the principal via `auth.GetAuthDataAPI(r)` |
| `GET /api/admin` | Bearer JWT + `admin` role | Protecting a **native framework handler** by adapting the net/http middleware, and reading claims inside it |
| `GET /dashboard` | Session cookie | `UseWEBAuthorization` — unauthenticated requests are 307-redirected to `/sign-in?redirectUrl=...` |

All examples use SQLite (pure Go driver, no cgo) so there is nothing to install, and they seed one demo user (`00000000-0000-0000-0000-000000000001` with role `admin:rw`) that `ResolveUser` returns.

## Running an example

```bash
cd examples/fiber   # or examples/gin, examples/echo
go run .
```

The server listens on `http://localhost:3000`. Each example has its own `go.mod` with a `replace` directive pointing at the parent module, so local changes to goauth are picked up immediately.

## Trying it out

List the configured providers:

```bash
curl http://localhost:3000/api/authorization/providers
```

Get the Google authorization URL as JSON (a real sign-in requires real client credentials in `main.go`):

```bash
curl "http://localhost:3000/api/authorization/provider/google?json=true"
```

Hit a protected API route — expect `401` without a token:

```bash
curl -i http://localhost:3000/api/profile
```

Hit the cookie-protected page — expect a `307` redirect to the sign-in URL:

```bash
curl -i http://localhost:3000/dashboard
```

To test with a valid token end to end, configure real OAuth credentials and complete the sign-in flow in a browser; the callback page returns an access/refresh token pair and sets the session cookie. Then:

```bash
curl -H "Authorization: Bearer <access_token>" http://localhost:3000/api/profile
curl -H "Authorization: Bearer <access_token>" http://localhost:3000/api/admin
```

## Adapting to another framework

If your framework is not listed here, the recipe is always the same:

1. Find (or write) its `http.Handler -> framework handler` adapter and wrap `auth.Handler()`.
2. Find (or write) its `func(http.Handler) http.Handler -> framework middleware` adapter and wrap `auth.UseAPIAuthorization(...)` / `auth.UseWEBAuthorization(...)`.
3. Make sure the adapter propagates the request **context** back into the framework, so `auth.GetClaims(r)` works in downstream handlers (see the Gin example's `wrapMiddleware` for a minimal reference implementation).

Frameworks built directly on `net/http` (chi, gorilla/mux, `http.ServeMux`) need no adapter at all.
