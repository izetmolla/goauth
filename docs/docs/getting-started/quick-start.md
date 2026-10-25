---
title: Quick start
description: A complete, runnable Google sign-in app with net/http and SQLite in about 100 lines.
---

# Quick start

This page builds a small but complete app:

- "Sign in with Google"
- a JSON API route protected by a JWT
- an HTML page protected by a session cookie

It uses only the standard library plus SQLite, so you can run it without any infrastructure.

## 1. Create a Google OAuth client

1. Open the [Google Cloud console → Credentials](https://console.cloud.google.com/apis/credentials).
2. Create an **OAuth client ID** of type **Web application**.
3. Add this **Authorized redirect URI**:

   ```text
   http://localhost:3000/api/authorization/provider/google/callback
   ```

4. Copy the client ID and secret into your shell:

```bash
export GOOGLE_CLIENT_ID="...apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="..."
export JWT_SECRET="$(openssl rand -hex 32)"
```

## 2. Create the project

```bash
mkdir goauth-quickstart && cd goauth-quickstart
go mod init example.com/quickstart
go get github.com/izetmolla/goauth github.com/glebarez/sqlite gorm.io/gorm github.com/google/uuid
```

## 3. Write `main.go`

```go title="main.go"
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/google"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(sqlite.Open("quickstart.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	if err := migrate(db); err != nil {
		log.Fatal(err)
	}

	auth, err := goauth.New(&goauth.Config{
		JWTSecret: os.Getenv("JWT_SECRET"),
		AuthURL:   "http://localhost:3000",
		DB:        db,
		Providers: []goauth.Provider{
			google.New(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")),
		},
		// Called after every successful OAuth sign-in. Find or create the
		// user in YOUR table and return its id and roles.
		ResolveUser: func(ctx context.Context, profile goauth.Profile) (*goauth.User, bool, error) {
			email, _ := profile["email"].(string)
			if email == "" {
				return nil, false, errors.New("provider returned no email")
			}
			var user struct {
				ID    string
				Roles goauth.JSONBArray
			}
			err := db.WithContext(ctx).Table("users").Select("id", "roles").
				Where("email = ?", email).Take(&user).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				user.ID = uuid.NewString()
				user.Roles = goauth.JSONBArray{"user:r"}
				err = db.WithContext(ctx).Exec(
					`INSERT INTO users (id, email, roles) VALUES (?, ?, ?)`,
					user.ID, email, user.Roles,
				).Error
				return &goauth.User{ID: user.ID, Roles: user.Roles}, true, err
			}
			if err != nil {
				return nil, false, err
			}
			return &goauth.User{ID: user.ID, Roles: user.Roles}, false, nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// Sign-in, callback and provider list under /api/authorization/.
	mux.Handle(goauth.DefaultBasePath+"/", auth.Handler())

	// Public pages.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<a href="/dashboard">Dashboard</a> · <a href="/sign-in">Sign in</a>`)
	})
	mux.HandleFunc("GET /sign-in", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<a href="/api/authorization/provider/google">Sign in with Google</a>`)
	})

	// JSON API protected by the access token (Authorization: Bearer <token>).
	mux.Handle("GET /api/me", auth.UseAPIAuthorization()(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			data, _ := auth.GetAuthDataAPI(r)
			_ = json.NewEncoder(w).Encode(data)
		})))

	// HTML page protected by the session cookie; redirects to /sign-in.
	mux.Handle("GET /dashboard", auth.UseWEBAuthorization()(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			data, _ := auth.GetAuthDataWEB(r, r.Context())
			fmt.Fprintf(w, "Hello user %s, roles %v", data.UserID, data.Roles)
		})))

	log.Println("listening on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", mux))
}

// migrate creates the two tables goauth reads: users and sessions.
func migrate(db *gorm.DB) error {
	return db.Exec(`
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
);`).Error
}
```

## 4. Run it

```bash
go run .
```

Open [http://localhost:3000/dashboard](http://localhost:3000/dashboard):

1. You have no session cookie, so `UseWEBAuthorization` redirects you to `/sign-in?redirectUrl=...`.
2. Click **Sign in with Google**. goauth redirects to Google with PKCE, `state` and `nonce`.
3. Google sends you back to `/api/authorization/provider/google/callback`. goauth exchanges the code, calls `ResolveUser`, creates a session row and sets the session cookie.
4. The callback page saves the tokens in `localStorage` (key `authorization-storage`) and redirects you to `/`.
5. Open `/dashboard` again: you are signed in.

## 5. Call the API with the access token

The callback page stored the token pair in the browser. Open the developer console and run:

```js
const s = JSON.parse(localStorage.getItem('authorization-storage'));
const t = s.sessions.find((x) => x.session_id === s.current_session).tokens;
console.log(t.access_token);
```

Then call the API:

```bash
curl -H "Authorization: Bearer <access_token>" http://localhost:3000/api/me
```

```json
{"SessionID":"","UserID":"5b1c...","Roles":["user:r"]}
```

The access token lives for 60 seconds by default. See [Tokens and refresh](../guides/tokens-and-refresh.md) to renew it.

## What's next

- Understand the moving parts: [Core concepts](./core-concepts.md)
- Use PostgreSQL instead of SQLite: [Database setup](./database-setup.md)
- Use your framework: [Fiber](../frameworks/fiber.mdx), [Echo](../frameworks/echo.mdx), [Gin](../frameworks/gin.mdx), [Chi](../frameworks/chi.mdx)
