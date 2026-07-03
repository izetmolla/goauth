# goauth + Echo v5

Runnable example that mounts [goauth](../../README.md) on an [Echo v5](https://echo.labstack.com) app.

Echo is built on `net/http` and ships **both** adapters natively, which makes it the smoothest integration of the three examples:

| Adapter | Converts | Used for |
|---------|----------|----------|
| `echo.WrapHandler(h)` | `http.Handler` → `echo.HandlerFunc` | Mounting `auth.Handler()` and pre-wrapped protected handlers |
| `echo.WrapMiddleware(mw)` | `func(http.Handler) http.Handler` → `echo.MiddlewareFunc` | Using goauth middlewares in front of native Echo handlers |

`echo.WrapMiddleware` swaps the context-enriched request back into the Echo context, so goauth helpers like `auth.GetClaims(c.Request())` work inside native Echo handlers out of the box.

## Run

```bash
go run .
```

Serves on `http://localhost:3000`. Uses SQLite (pure Go, no cgo) and seeds a demo admin user — see [`examples/README.md`](../README.md) for the routes and curl commands shared by all examples.

## Key integration points

Mount every goauth endpoint with one line:

```go
e.Any(goauth.DefaultBasePath+"/*", echo.WrapHandler(auth.Handler()))
```

Protect native Echo handlers and read the JWT claims downstream:

```go
adminOnly := echo.WrapMiddleware(auth.UseAPIAuthorization(
	auth.WithRoles([]string{"admin"}),
))
e.GET("/api/admin", func(c *echo.Context) error {
	claims, _ := auth.GetClaims(c.Request()) // works: Echo swaps in the enriched request
	return c.JSON(http.StatusOK, map[string]any{"user_id": claims["user_id"]})
}, adminOnly)
```

Cookie-protected pages:

```go
webAuth := echo.WrapMiddleware(auth.UseWEBAuthorization())
e.GET("/dashboard", func(c *echo.Context) error {
	return c.String(http.StatusOK, "welcome to your dashboard")
}, webAuth)
```

## Echo v5 notes

- Handlers take `*echo.Context` (a struct pointer) instead of the v4 `echo.Context` interface.
- `echo.Map` was removed in v5 — use `map[string]any`.
- The Echo instance itself is an `http.Handler`, so instead of `e.Start(":3000")` you can also serve it with a plain `http.Server{Handler: e}`.
