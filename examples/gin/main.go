// Example: mounting goauth (a pure net/http module) on a Gin app.
//
// goauth has no framework dependency. Its handlers are plain http.Handler /
// http.HandlerFunc values and its middlewares are func(http.Handler) http.Handler:
//
//   - gin.WrapH(h)          converts an http.Handler into a gin.HandlerFunc
//   - wrapMiddleware(mw)    (defined below) converts a net/http middleware
//     into a gin.HandlerFunc, since Gin has no built-in equivalent
//
// Run with:
//
//	go run .
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/google"
	"gorm.io/gorm"
)

// wrapMiddleware adapts a net/http middleware (func(http.Handler) http.Handler)
// to a gin.HandlerFunc. When the middleware calls its next handler, the chain
// continues with the (possibly context-enriched) request; when it writes a
// response itself (e.g. a 401), the gin chain is aborted.
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

func main() {
	db, err := gorm.Open(sqlite.Open("goauth-example.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	if err := migrate(db); err != nil {
		log.Fatalf("migrate: %v", err)
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
			return &goauth.User{
				ID:    "00000000-0000-0000-0000-000000000001",
				Roles: goauth.JSONBArray{"admin:rw"},
			}, false, nil
		},
	})
	if err != nil {
		log.Fatalf("init goauth: %v", err)
	}

	r := gin.Default()

	// 1. Mount every goauth endpoint (providers list, sign-in, OAuth callback)
	//    in one shot. auth.Handler() is a plain http.Handler serving:
	//
	//      GET {base}/providers
	//      ANY {base}/provider/{provider}
	//      ANY {base}/provider/{provider}/callback
	//
	//    where {base} is goauth.DefaultBasePath (/api/authorization).
	r.Any(goauth.DefaultBasePath+"/*path", gin.WrapH(auth.Handler()))

	// 2. Refresh-token endpoint: goauth.HandleRefreshToken is a net/http
	//    middleware that only activates when the client sends the opt-in
	//    header ("cft"); otherwise it falls through to the next handler.
	r.POST("/api/token/refresh", gin.WrapH(
		auth.HandleRefreshToken(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.Error(w, "refresh header missing", http.StatusBadRequest)
		})),
	))

	// 3. Protect a route with the JWT (API) middleware. The handler itself is
	//    written against net/http, so goauth helpers like GetAuthDataAPI work
	//    directly on *http.Request.
	profile := auth.UseAPIAuthorization()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		data, err := auth.GetAuthDataAPI(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user_id":"` + data.UserID + `"}`))
	}))
	r.GET("/api/profile", gin.WrapH(profile))

	// 4. Alternatively, protect *native Gin handlers* by converting the
	//    net/http middleware with wrapMiddleware. Because the middleware puts
	//    the JWT on the request context and c.Request is swapped for the
	//    enriched request, goauth.GetClaims(c.Request) also works here.
	adminOnly := wrapMiddleware(auth.UseAPIAuthorization(
		auth.WithRoles([]string{"admin"}),
	))
	r.GET("/api/admin", adminOnly, func(c *gin.Context) {
		claims, _ := auth.GetClaims(c.Request)
		c.JSON(http.StatusOK, gin.H{
			"message": "hello, admin",
			"user_id": claims["user_id"],
		})
	})

	// 5. Cookie-based protection for server-rendered pages: unauthenticated
	//    requests are redirected to the sign-in URL.
	webAuth := wrapMiddleware(auth.UseWEBAuthorization(
		auth.WithExcludedPaths([]string{"/dashboard/public"}),
	))
	r.GET("/dashboard", webAuth, func(c *gin.Context) {
		c.String(http.StatusOK, "welcome to your dashboard")
	})

	log.Fatal(r.Run(":3000"))
}

// migrate creates the demo tables. goauth's Session model declares Postgres
// defaults (gen_random_uuid()), so for this SQLite demo the tables are created
// with plain SQL. Session IDs are generated in Go by the model's BeforeCreate
// hook regardless.
func migrate(db *gorm.DB) error {
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
		return err
	}
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		roles TEXT DEFAULT '[]',
		content TEXT DEFAULT '{}'
	)`).Error; err != nil {
		return err
	}
	// Seed the demo user returned by ResolveUser.
	return db.Exec(`INSERT OR IGNORE INTO users (id, roles) VALUES
		('00000000-0000-0000-0000-000000000001', '["admin:rw"]')`).Error
}
