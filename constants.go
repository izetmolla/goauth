package goauth

import "time"

// Header identifiers used by the package's middlewares to coordinate
// optional flows such as refresh-token issuance and re-goauth.
const (
	RefreshTokenHandlerIdentifier = "cft"
	ReauthorizeHandlerIdentifier  = "cra"
)

// Token, session and cookie defaults. They are exposed as variables so
// downstream modules that have to interoperate with this package can
// override them for tests without forking the package.
var (
	DefaultUserTableName    = "users"
	DefaultSessionTableName = "sessions"

	DefaultAccessTokenDuration  = "60s"
	DefaultRefreshTokenDuration = "1y"
	DefaultSigningMethodHMAC    = "HS256"

	DefaultRedisTTL    = 30 * time.Minute
	DefaultRedisPrefix = "AUTHSESSIONS"

	DefaultCookieSessionName = "cnf.id"
	DefaultSignInRedirectURL = "/sign-in"
)
