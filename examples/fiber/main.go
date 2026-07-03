// Example: mounting goauth (a pure net/http module) on a Fiber v3 app using
// Fiber's adaptor middleware.
//
// goauth no longer depends on Fiber. Its handlers are plain http.Handler /
// http.HandlerFunc values and its middlewares are func(http.Handler) http.Handler,
// so they plug into Fiber through github.com/gofiber/fiber/v3/middleware/adaptor:
//
//   - adaptor.HTTPHandler(h)      converts an http.Handler into a fiber.Handler
//   - adaptor.HTTPHandlerFunc(f)  converts an http.HandlerFunc into a fiber.Handler
//   - adaptor.HTTPMiddleware(mw)  converts a net/http middleware into a fiber.Handler
//
// Run with:
//
//	go run .
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/glebarez/sqlite"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/google"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(sqlite.Open("goauth-example.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	// goauth's Session model declares Postgres defaults (gen_random_uuid()),
	// so for this SQLite demo the tables are created with plain SQL. Session
	// IDs are generated in Go by the model's BeforeCreate hook regardless.
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT,
		type TEXT DEFAULT 'sign_in',
		ip_address TEXT,
		user_agent TEXT,
		method TEXT DEFAULT 'credentials',
		account TEXT,
		expires_at DATETIME,
		is_deleted NUMERIC DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME,
		deleted_at DATETIME
	)`).Error; err != nil {
		log.Fatalf("migrate sessions: %v", err)
	}
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		roles TEXT DEFAULT '[]',
		content TEXT DEFAULT '{}'
	)`).Error; err != nil {
		log.Fatalf("migrate users: %v", err)
	}
	// Seed the demo user returned by ResolveUser below.
	if err := db.Exec(`INSERT OR IGNORE INTO users (id, roles) VALUES
		('00000000-0000-0000-0000-000000000001', '["admin:rw"]')`).Error; err != nil {
		log.Fatalf("seed user: %v", err)
	}

	auth, err := goauth.New(&goauth.Config{
		JWTSecret: "super-secret-change-me",
		AuthURL:   "http://localhost:3000",
		DB:        db,
		Providers: []goauth.Provider{
			google.New("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"),
		},
		// ResolveUser maps the provider profile to a user in your database.
		ResolveUser: func(ctx context.Context, profile goauth.Profile) (*goauth.User, bool, error) {
			// Look the user up (or create it) here. This demo just returns a
			// static user so the flow can complete.
			return &goauth.User{
				ID:    "00000000-0000-0000-0000-000000000001",
				Roles: goauth.JSONBArray{"admin:rw"},
			}, false, nil
		},
	})
	if err != nil {
		log.Fatalf("init goauth: %v", err)
	}

	app := fiber.New()

	// 1. Mount every goauth endpoint (providers list, sign-in, OAuth callback)
	//    in one shot. auth.Handler() is a plain http.Handler serving:
	//
	//      GET {base}/providers
	//      ANY {base}/provider/{provider}
	//      ANY {base}/provider/{provider}/callback
	//
	//    where {base} is goauth.DefaultBasePath (/api/authorization).
	authHandler := adaptor.HTTPHandler(auth.Handler())
	app.All(goauth.DefaultBasePath+"/*", authHandler)

	// 2. Refresh-token endpoint: goauth.HandleRefreshToken is a net/http
	//    middleware that only activates when the client sends the opt-in
	//    header ("cft"); otherwise it falls through to the next handler.
	app.Post("/api/token/refresh", adaptor.HTTPHandler(
		auth.HandleRefreshToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "refresh header missing", http.StatusBadRequest)
		})),
	))

	// 3. Protect a route with the JWT (API) middleware. The handler itself is
	//    written against net/http, so goauth helpers like GetAuthDataAPI work
	//    directly on *http.Request.
	profile := auth.UseAPIAuthorization()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := auth.GetAuthDataAPI(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user_id":"` + data.UserID + `"}`))
	}))
	app.Get("/api/profile", adaptor.HTTPHandler(profile))

	// 4. Alternatively, protect *native Fiber handlers* by converting the
	//    net/http middleware with adaptor.HTTPMiddleware. Everything after it
	//    in the chain stays idiomatic Fiber.
	adminOnly := adaptor.HTTPMiddleware(auth.UseAPIAuthorization(
		auth.WithRoles([]string{"admin"}),
	))
	app.Get("/api/admin", adminOnly, func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "hello, admin"})
	})

	// 5. Cookie-based protection for server-rendered pages: unauthenticated
	//    requests are redirected to the sign-in URL.
	webAuth := adaptor.HTTPMiddleware(auth.UseWEBAuthorization(
		auth.WithExcludedPaths([]string{"/dashboard/public"}),
	))
	app.Get("/dashboard", webAuth, func(c fiber.Ctx) error {
		return c.SendString("welcome to your dashboard")
	})

	log.Fatal(app.Listen(":3000"))
}
