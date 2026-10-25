---
title: Protecting web pages
description: Use UseWEBAuthorization for server-rendered pages with a session cookie and sign-in redirects.
---

# Protecting web pages

`auth.UseWEBAuthorization` protects server-rendered pages with the **session cookie** set at sign-in.

## Basic usage

```go
dashboard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	data, err := auth.GetAuthDataWEB(r, r.Context())
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tmpl.Execute(w, data)
})

mux.Handle("GET /dashboard", auth.UseWEBAuthorization()(dashboard))
```

## What happens on each request

1. Reads the session id from the session cookie (`cnf.id` by default).
2. Loads the session row (or the Redis copy) and the user's current `roles`.
3. Checks that the session is not signed out (`is_deleted`) and not expired.
4. Applies `WithRoles`, if set.

When the cookie is missing, unknown, signed out or expired, the user is redirected (`307`):

```text
/sign-in?redirectUrl=https%3A%2F%2Fapp.example.com%2Fdashboard%3Ftab%3Dbilling
```

The target is `Config.SignInRedirectURL` (default `/sign-in`). Database errors return `500` JSON instead of redirecting.

## A sign-in page that returns the user

Use `redirectUrl` to send users back after sign-in. Only accept **relative** paths, to avoid open redirects:

```go
mux.HandleFunc("GET /sign-in", func(w http.ResponseWriter, r *http.Request) {
	back := safeRedirect(r.URL.Query().Get("redirectUrl"))
	fmt.Fprintf(w, `<!doctype html>
<h1>Sign in</h1>
<a href="/api/authorization/provider/google" onclick="remember()">Continue with Google</a>
<script>
function remember() {
  const k = 'authorization-storage';
  const s = JSON.parse(localStorage.getItem(k) || '{"sessions":[],"current_session":""}');
  s.redirectUrl = %q;
  localStorage.setItem(k, JSON.stringify(s));
}
</script>`, back)
})

// safeRedirect keeps only same-site paths such as "/dashboard?tab=1".
func safeRedirect(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return "/"
	}
	if u.Host != "" { // absolute URL: keep only the path and query
		u = &url.URL{Path: u.Path, RawQuery: u.RawQuery}
	}
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return u.String()
}
```

The callback page reads `redirectUrl` from `localStorage` after a successful sign-in.

## Role gates and excluded paths

```go
admin := auth.UseWEBAuthorization(
	auth.WithRoles([]string{"admin"}),
	auth.WithExcludedPaths([]string{"/admin/login"}),
)
mux.Handle("/admin/", admin(adminRouter))
```

A signed-in user without the role gets a `403` JSON response. Render a friendlier page by checking roles yourself:

```go
data, _ := auth.GetAuthDataWEB(r, r.Context())
if ok, _, _ := auth.GetRole([]string{"admin"}, data.Roles); !ok {
	w.WriteHeader(http.StatusForbidden)
	tmpl.ExecuteTemplate(w, "forbidden.html", nil)
	return
}
```

## Optional authentication

For pages that look different when signed in but stay public, skip the middleware and read the session directly:

```go
func home(w http.ResponseWriter, r *http.Request) {
	data, err := auth.GetAuthDataWEB(r, r.Context())
	signedIn := err == nil
	tmpl.Execute(w, map[string]any{"SignedIn": signedIn, "User": data})
}
```

`GetAuthDataWEB` returns `goauth.ErrSessionNotFound` or `goauth.ErrSessionExpired` for anonymous visitors.

## CSRF for your own forms

The session cookie is `SameSite=Lax`, which blocks cross-site `POST` requests in modern browsers. For defense in depth, protect state-changing forms with a CSRF token, or use Go's built-in [`http.CrossOriginProtection`](https://pkg.go.dev/net/http#CrossOriginProtection):

```go
csrf := http.NewCrossOriginProtection()
log.Fatal(http.ListenAndServe(":3000", csrf.Handler(mux)))
```

## Session-cookie pages and APIs together

A common setup protects HTML pages with cookies and JSON with tokens:

```go
mux.Handle("/app/", auth.UseWEBAuthorization()(appPages))
mux.Handle("/api/", auth.UseAPIAuthorization()(apiRoutes))
```

The session cookie and the token pair come from the same sign-in, so one OAuth round trip serves both.
