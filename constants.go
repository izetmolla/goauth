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
	// DefaultTablePrefix is prepended to the names of the tables goauth owns
	// (verification tokens, TOTP factors, login attempts, IP access rules),
	// keeping them apart from your own tables. Change it in your package's
	// init function, or per instance with Config.TablePrefix. Set it to ""
	// for unprefixed names. It does not apply to the users and sessions
	// tables, which have their own settings.
	DefaultTablePrefix = "goauth_"

	DefaultUserTableName    = "users"
	DefaultSessionTableName = "sessions"

	DefaultAccessTokenDuration  = "60s"
	DefaultRefreshTokenDuration = "1y"
	DefaultSigningMethodHMAC    = "HS256"

	DefaultRedisTTL    = 30 * time.Minute
	DefaultRedisPrefix = "AUTHSESSIONS"

	DefaultCookieSessionName = "cnf.id"
	DefaultSignInRedirectURL = "/sign-in"

	// DefaultBasePath is the URL prefix under which Handler mounts the
	// authorization endpoints.
	DefaultBasePath = "/api/authorization"
)
