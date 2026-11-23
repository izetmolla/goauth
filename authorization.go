package goauth

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// ConfigFunc adjusts a Config before New validates it. ConfigFuncs are
// applied to a copy, so the Config passed to New is never modified.
type ConfigFunc func(cfg *Config)

// Config configures New. Only JWTSecret and DB are required; other fields
// fall back to the matching Default* package variable or stay off.
type Config struct {
	JWTSecret            string
	AuthURL              string
	SigningMethod        string
	AccessTokenDuration  string
	RefreshTokenDuration string
	SignInRedirectURL    string

	DB          *gorm.DB
	Redis       *redis.Client
	RedisPrefix string

	UserTableName    string
	SessionTableName string
	// TablePrefix is prepended to the names of the tables goauth owns:
	// {prefix}verification_tokens, {prefix}totp, {prefix}login_attempts,
	// and {prefix}ip_access_rules. Empty uses DefaultTablePrefix ("goauth_").
	// An explicit Verification.TableName, MFA.TOTP.TableName,
	// LoginProtection.TableName, or IPAccess.TableName is used as is.
	TablePrefix string
	// AutoMigrate runs Migrate during New when true: creates missing
	// sessions / feature tables and adds missing columns. Off by default.
	// Does not touch the users table. Prefer this in development and small
	// deployments; use Migrate (or your own migration tool) in production
	// when you want migrations outside of process start.
	AutoMigrate bool
	RedisTTL    time.Duration

	// Providers is the ordered list of enabled providers. Required.
	Providers []Provider

	CookieSessionName string
	Cookies           *CookieOptions

	ResolveUser func(ctx context.Context, profile Profile) (*User, bool, error)

	// OnProviderConnect persists extended OAuth scopes after a connect flow when
	// resource_id was supplied on the authorization request.
	OnProviderConnect func(ctx context.Context, resourceID string, account *Account, user *User, providerID string) error

	// KeepRefreshTokenServerSide stops the OAuth callback page from handing
	// the refresh token to the browser (where it would land in localStorage
	// and be readable by any XSS). Web clients then refresh with the HttpOnly
	// session cookie: the refresh endpoint and CheckSession accept it when the
	// request carries no refresh token. Off by default for compatibility with
	// frontends that read tokens.refresh_token from localStorage.
	KeepRefreshTokenServerSide bool

	// Endpoints switches individual built-in endpoints off. Every endpoint
	// is enabled by default (the zero value).
	Endpoints EndpointOptions

	// UI brands the built-in pages and verification emails.
	UI UIOptions

	// Verification enables password reset, email confirmation and
	// one-time-code sign-in. All are off by default.
	Verification VerificationOptions

	// MFA configures authenticator-app (TOTP) multi-factor authentication.
	// Off by default; when enabled, users with an enrolled factor must
	// complete a TOTP challenge before any session is created.
	MFA MFAOptions

	// LoginAs configures admin impersonation (GET/POST {base}/login_as).
	// Off by default.
	LoginAs LoginAsOptions

	// LoginProtection persists failed credentials attempts and locks an
	// identifier after too many wrong passwords. Off by default; when
	// Enabled, MaxFailures and LockoutFor must be set explicitly.
	LoginProtection LoginProtectionOptions

	// IPAccess enables whitelist / blacklist tables and enforces them on
	// every goauth HTTP request. Off by default.
	IPAccess IPAccessOptions

	// TrustedProxies lists the reverse proxies (IPs or CIDRs, such as
	// "10.0.0.0/8") whose CF-Connecting-IP, X-Forwarded-For and X-Real-IP
	// headers are believed when IPAccess, LoginProtection and session
	// metadata determine the client address. Empty means the headers are
	// ignored and the TCP peer address is used, so set it when goauth runs
	// behind a load balancer.
	TrustedProxies []string
	// TrustCloudflare merges Cloudflare's published edge CIDRs into
	// TrustedProxies and prefers the CF-Connecting-IP header for the client
	// address. Use this when the app sits behind Cloudflare (orange cloud or
	// tunnel). You can still add private load-balancer ranges in TrustedProxies.
	TrustCloudflare bool

	// TrustedRedirectOrigins are extra http(s) origins allowed in post-sign-in
	// redirectUrl values (in addition to AuthURL / same-origin paths). Use
	// this when UseWEBAuthorization on another app sends users here with
	// redirectUrl=https://app.example.com/…. Empty rejects all foreign
	// absolute redirects.
	TrustedRedirectOrigins []string
}

// Authorization is the configured authentication service. Create it once
// with New; it is safe for concurrent use. The With* setters are meant for
// startup and tests only.
type Authorization struct {
	JWTSecret            string
	AuthURL              string
	signingMethod        string
	accessTokenDuration  string
	refreshTokenDuration string
	signInRedirectURL    string
	db                   *gorm.DB

	redis       *redis.Client
	redisPrefix string
	redisTTL    time.Duration

	userTableName    string
	sessionTableName string

	cookieSessionName string

	providers []Provider

	cookies           CookieOptions
	resolveUser       func(ctx context.Context, profile Profile) (*User, bool, error)
	onProviderConnect func(ctx context.Context, resourceID string, account *Account, user *User, providerID string) error

	keepRefreshTokenServerSide bool

	endpoints EndpointOptions
	ui        UIOptions
	verify    *verification
	totp      *totpMFA
	loginAs   *loginAsFeature
	loginProt *loginProtection
	ipAccess  *ipAccess
	// trustedProxies are parsed Config.TrustedProxies.
	trustedProxies []*net.IPNet
	// trustedRedirectOrigins are normalized "scheme://host" values from
	// Config.TrustedRedirectOrigins.
	trustedRedirectOrigins []string
	pages                  map[string]string // page name -> path, only pages that are on

	// Resolved once in New so hot paths never re-parse configuration.
	accessTTL  time.Duration
	refreshTTL time.Duration
	method     *jwt.SigningMethodHMAC
	parser     *jwt.Parser
}

// New builds an Authorization from config. Optional ConfigFunc values are
// applied on top of config, and any field still left empty falls back to the
// package defaults (DefaultAccessTokenDuration, DefaultRedisPrefix, ...).
func New(config *Config, opts ...ConfigFunc) (*Authorization, error) {
	if config == nil {
		return nil, errors.New("config is required")
	}
	cfg := *config
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.JWTSecret == "" {
		return nil, errors.New("JWTSecret is required")
	}
	if cfg.DB == nil {
		return nil, errors.New("db is required")
	}

	// Invalid durations or algorithms fail here, at startup, instead of on
	// the first sign-in.
	accessTTL, err := ParseCustomDuration(cfg.AccessTokenDuration, DefaultAccessTokenDuration)
	if err != nil {
		return nil, fmt.Errorf("invalid AccessTokenDuration: %w", err)
	}
	refreshTTL, err := ParseCustomDuration(cfg.RefreshTokenDuration, DefaultRefreshTokenDuration)
	if err != nil {
		return nil, fmt.Errorf("invalid RefreshTokenDuration: %w", err)
	}
	method, err := signingMethodFor(cmp.Or(cfg.SigningMethod, DefaultSigningMethodHMAC))
	if err != nil {
		return nil, err
	}
	if cfg.AuthURL != "" {
		if _, _, err := parseOriginURL(cfg.AuthURL); err != nil {
			return nil, err
		}
	}
	if err := validateProviders(cfg.Providers); err != nil {
		return nil, err
	}

	if err := cfg.UI.validate(); err != nil {
		return nil, err
	}
	prefix := cmp.Or(cfg.TablePrefix, DefaultTablePrefix)
	verify, err := newVerification(cfg.Verification, cfg.JWTSecret, prefix)
	if err != nil {
		return nil, fmt.Errorf("verification: %w", err)
	}
	totp, err := newTOTP(cfg.MFA.TOTP, cfg.JWTSecret, cfg.UI.AppName, prefix)
	if err != nil {
		return nil, fmt.Errorf("mfa: %w", err)
	}
	loginAs, err := newLoginAs(cfg.LoginAs)
	if err != nil {
		return nil, fmt.Errorf("login_as: %w", err)
	}
	loginProt, err := newLoginProtection(cfg.LoginProtection, prefix)
	if err != nil {
		return nil, fmt.Errorf("login_protection: %w", err)
	}
	ipAccess, err := newIPAccess(cfg.IPAccess, prefix)
	if err != nil {
		return nil, fmt.Errorf("ip_access: %w", err)
	}
	trustedProxies, err := parseTrustedProxies(cfg.TrustedProxies, cfg.TrustCloudflare)
	if err != nil {
		return nil, err
	}
	trustedRedirectOrigins, err := parseTrustedRedirectOrigins(cfg.TrustedRedirectOrigins)
	if err != nil {
		return nil, err
	}

	var cookies CookieOptions
	if cfg.Cookies != nil {
		cookies = *cfg.Cookies
	}
	a := &Authorization{
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		method:     method,
		parser:     newJWTParser(method),

		JWTSecret:            cfg.JWTSecret,
		AuthURL:              cfg.AuthURL,
		signingMethod:        cmp.Or(cfg.SigningMethod, DefaultSigningMethodHMAC),
		accessTokenDuration:  cmp.Or(cfg.AccessTokenDuration, DefaultAccessTokenDuration),
		refreshTokenDuration: cmp.Or(cfg.RefreshTokenDuration, DefaultRefreshTokenDuration),
		signInRedirectURL:    cmp.Or(cfg.SignInRedirectURL, DefaultSignInRedirectURL),
		db:                   cfg.DB,
		redis:                cfg.Redis,
		redisPrefix:          cmp.Or(cfg.RedisPrefix, DefaultRedisPrefix),
		redisTTL:             cmp.Or(cfg.RedisTTL, DefaultRedisTTL),
		userTableName:        cmp.Or(cfg.UserTableName, DefaultUserTableName),
		sessionTableName:     cmp.Or(cfg.SessionTableName, DefaultSessionTableName),
		cookieSessionName:    cmp.Or(cfg.CookieSessionName, DefaultCookieSessionName),
		providers:            cfg.Providers,
		cookies:              cookies,
		resolveUser:          cfg.ResolveUser,
		onProviderConnect:    cfg.OnProviderConnect,

		keepRefreshTokenServerSide: cfg.KeepRefreshTokenServerSide,
		endpoints:                  cfg.Endpoints,
		ui:                         cfg.UI,
		verify:                     verify,
		totp:                       totp,
		loginAs:                    loginAs,
		loginProt:                  loginProt,
		ipAccess:                   ipAccess,
		trustedProxies:             trustedProxies,
		trustedRedirectOrigins:     trustedRedirectOrigins,
	}
	if err := a.resolvePages(cfg.UI); err != nil {
		return nil, err
	}
	// A link must open a page. With a feature's page off, its emails carry
	// only a code, unless links were asked for explicitly.
	for _, f := range []struct {
		feat     *verifyFeature
		page     string
		delivery Delivery
		field    string
	}{
		{&verify.reset, pageForgot, cfg.Verification.PasswordReset.Code.Delivery, "PasswordReset"},
		{&verify.confirm, pageVerify, cfg.Verification.EmailConfirmation.Code.Delivery, "EmailConfirmation"},
		{&verify.otp, pageOTP, cfg.Verification.OTPSignIn.Code.Delivery, "OTPSignIn"},
	} {
		if !f.feat.enabled || !f.feat.code.Delivery.hasLink() || a.pagePath(f.page) != "" {
			continue
		}
		if f.delivery != DeliverDefault {
			return nil, fmt.Errorf("verification: %s.Code.Delivery sends links, which open the %s page; turn that page on in UIOptions (or EnableAllUI), or use Delivery: goauth.DeliverCode", f.field, f.page)
		}
		f.feat.code.Delivery = DeliverCode
	}
	if cfg.AutoMigrate {
		if err := a.Migrate(context.Background()); err != nil {
			return nil, fmt.Errorf("auto migrate: %w", err)
		}
	}
	return a, nil
}

// validateProviders rejects provider lists that would fail at request time:
// nil entries, empty or duplicate ids, and OAuth providers without Profile.
func validateProviders(providers []Provider) error {
	seen := make(map[string]bool, len(providers))
	for i, p := range providers {
		if p == nil {
			return fmt.Errorf("provider %d is nil", i)
		}
		id := p.ID()
		switch {
		case id == "":
			return fmt.Errorf("provider %d has an empty id", i)
		case seen[id]:
			return fmt.Errorf("duplicate provider id %q", id)
		}
		seen[id] = true
		if op, ok := p.(*OAuthProvider); ok && op.Profile == nil {
			return fmt.Errorf("provider %q has no Profile function", id)
		}
	}
	return nil
}

// WithJWTSecret replaces the signing secret. Empty values are ignored.
// Setters are for startup and tests; they are not synchronized with requests.
func (a *Authorization) WithJWTSecret(secret string) *Authorization {
	if a != nil && secret != "" {
		a.JWTSecret = secret
	}
	return a
}

// WithAuthURL replaces the public origin. Empty values are ignored.
func (a *Authorization) WithAuthURL(authURL string) *Authorization {
	if a != nil && authURL != "" {
		a.AuthURL = authURL
	}
	return a
}

// WithDB replaces the database. Nil values are ignored.
func (a *Authorization) WithDB(db *gorm.DB) *Authorization {
	if a != nil && db != nil {
		a.db = db
	}
	return a
}

// WithRedis sets the Redis client sessions are copied to. Nil is ignored.
func (a *Authorization) WithRedis(redis *redis.Client) *Authorization {
	if a != nil && redis != nil {
		a.redis = redis
	}
	return a
}

// WithRedisPrefix replaces the Redis key prefix. Empty values are ignored.
func (a *Authorization) WithRedisPrefix(redisPrefix string) *Authorization {
	if a != nil && redisPrefix != "" {
		a.redisPrefix = redisPrefix
	}
	return a
}

// WithRedisTTL replaces the Redis entry lifetime. Non-positive values are
// ignored.
func (a *Authorization) WithRedisTTL(redisTTL time.Duration) *Authorization {
	if a != nil && redisTTL > 0 {
		a.redisTTL = redisTTL
	}
	return a
}

// WithCookieSessionName replaces the session cookie name. Empty values are
// ignored.
func (a *Authorization) WithCookieSessionName(cookieSessionName string) *Authorization {
	if a != nil && cookieSessionName != "" {
		a.cookieSessionName = cookieSessionName
	}
	return a
}

// WithResolveUser replaces Config.ResolveUser. Nil is ignored.
func (a *Authorization) WithResolveUser(resolveUser func(ctx context.Context, profile Profile) (*User, bool, error)) *Authorization {
	if a != nil && resolveUser != nil {
		a.resolveUser = resolveUser
	}
	return a
}
