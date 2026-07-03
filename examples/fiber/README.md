# goauth + Fiber v3

Runnable example that mounts [goauth](../../README.md) on a [Fiber v3](https://gofiber.io) app using Fiber's official adaptor middleware, `github.com/gofiber/fiber/v3/middleware/adaptor`.

Fiber is built on fasthttp rather than `net/http`, so the adaptor converts between the two worlds:

| Adapter | Converts | Used for |
|---------|----------|----------|
| `adaptor.HTTPHandler(h)` | `http.Handler` → `fiber.Handler` | Mounting `auth.Handler()` and pre-wrapped protected handlers |
| `adaptor.HTTPMiddleware(mw)` | `func(http.Handler) http.Handler` → `fiber.Handler` | Using goauth middlewares in front of native Fiber handlers |

## Run

```bash
go run .
```

Serves on `http://localhost:3000`. Uses SQLite (pure Go, no cgo) and seeds a demo admin user — see [`examples/README.md`](../README.md) for the routes and curl commands shared by all examples.

## Key integration points

Mount every goauth endpoint with one line:

```go
app.All(goauth.DefaultBasePath+"/*", adaptor.HTTPHandler(auth.Handler()))
```

Protect native Fiber handlers with the net/http middleware — note that with Fiber the middleware must be registered **before** the final handler in the route chain (handlers execute in registration order):

```go
adminOnly := adaptor.HTTPMiddleware(auth.UseAPIAuthorization(
	auth.WithRoles([]string{"admin"}),
))
app.Get("/api/admin", adminOnly, func(c fiber.Ctx) error {
	return c.JSON(fiber.Map{"message": "hello, admin"})
})
```

Protect a handler written against `net/http` (recommended when you need goauth helpers like `GetAuthDataAPI`):

```go
profile := auth.UseAPIAuthorization()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	data, _ := auth.GetAuthDataAPI(r)
	// ...
}))
app.Get("/api/profile", adaptor.HTTPHandler(profile))
```

## Caveat: reading claims in native Fiber handlers

`adaptor.HTTPMiddleware` copies request-context values back into Fiber's fasthttp context using reflection (`CopyContextToFiberContext`), which the Fiber docs themselves mark as deprecated/fragile. Reading goauth's JWT claims from inside a *native* Fiber handler may work but is not guaranteed across Fiber versions.

**Recommendation:** when a handler needs the authenticated principal, keep it in `net/http` land (pattern shown above for `/api/profile`) where `auth.GetClaims(r)` / `auth.GetAuthDataAPI(r)` are fully supported. Use `adaptor.HTTPMiddleware` only for routes that just need the gate (401/403/redirect) without reading claims downstream.
