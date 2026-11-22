// Package goauth is a framework-agnostic authentication and authorization
// module built on net/http.
//
// It provides OAuth 2.0 / OpenID Connect sign-in with more than 80 provider
// presets, credentials sign-in and sign-up, passkeys, TOTP multi-factor
// authentication, email verification, password reset and one-time-code
// sign-in, JWT access and refresh tokens, database-backed sessions (GORM),
// CSRF-protected cookies, role-based access control, admin "login as", and
// optional built-in HTML pages.
//
// Create one Authorization at startup with New, mount Authorization.Handler,
// and protect routes with Authorization.UseAPIAuthorization (Bearer JWT) or
// Authorization.UseWEBAuthorization (session cookie):
//
//	auth, err := goauth.New(&goauth.Config{
//		JWTSecret:   os.Getenv("JWT_SECRET"),
//		DB:          db,
//		Providers:   []goauth.Provider{google.New(clientID, clientSecret)},
//		ResolveUser: resolveUser,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	mux.Handle(goauth.DefaultBasePath+"/", auth.Handler())
//	mux.Handle("GET /api/me", auth.UseAPIAuthorization()(me))
//
// Every handler is an http.Handler and every middleware is a
// func(http.Handler) http.Handler, so goauth works with the standard library
// and with Fiber, Echo, Gin, Chi and other routers.
package goauth
