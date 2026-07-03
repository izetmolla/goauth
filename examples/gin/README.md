# goauth + Gin

Runnable example that mounts [goauth](../../README.md) on a [Gin](https://gin-gonic.com) app.

Gin is built on `net/http`, so handlers convert with the built-in `gin.WrapH`. Gin has **no built-in adapter for net/http middleware**, so this example includes a small `wrapMiddleware` helper (~12 lines in [`main.go`](main.go)) that you can copy into your own project.

| Adapter | Converts | Used for |
|---------|----------|----------|
| `gin.WrapH(h)` (built in) | `http.Handler` → `gin.HandlerFunc` | Mounting `auth.Handler()` and pre-wrapped protected handlers |
| `wrapMiddleware(mw)` (in this example) | `func(http.Handler) http.Handler` → `gin.HandlerFunc` | Using goauth middlewares in front of native Gin handlers |

## Run

```bash
go run .
```

Serves on `http://localhost:3000`. Uses SQLite (pure Go, no cgo) and seeds a demo admin user — see [`examples/README.md`](../README.md) for the routes and curl commands shared by all examples.

## Key integration points

Mount every goauth endpoint with one line — Gin requires a **named** wildcard (`/*path`):

```go
r.Any(goauth.DefaultBasePath+"/*path", gin.WrapH(auth.Handler()))
```

The middleware adapter: it runs the goauth middleware and, only if the middleware called its next handler, swaps `c.Request` for the context-enriched request and continues the Gin chain; otherwise it aborts, letting goauth's own 401/403/redirect response stand:

```go
func wrapMiddleware(mw func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		passed := false
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			passed = true
			c.Request = r
			c.Next()
		})).ServeHTTP(c.Writer, c.Request)
		if !passed {
			c.Abort()
		}
	}
}
```

Because the enriched request is swapped into the Gin context, goauth helpers work directly inside native Gin handlers:

```go
adminOnly := wrapMiddleware(auth.UseAPIAuthorization(
	auth.WithRoles([]string{"admin"}),
))
r.GET("/api/admin", adminOnly, func(c *gin.Context) {
	claims, _ := auth.GetClaims(c.Request) // works: request carries the JWT context
	c.JSON(http.StatusOK, gin.H{"user_id": claims["user_id"]})
})
```

Cookie-protected pages:

```go
webAuth := wrapMiddleware(auth.UseWEBAuthorization())
r.GET("/dashboard", webAuth, func(c *gin.Context) {
	c.String(http.StatusOK, "welcome to your dashboard")
})
```
