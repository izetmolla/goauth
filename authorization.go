package goauth

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type ConfigFunc func(cfg *Config)
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
	RedisTTL         time.Duration

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
}
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
	pages     map[string]string // page name -> path, only pages that are on

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

	if err := cfg.UI.validate(); err != nil {
		return nil, err
	}
	verify, err := newVerification(cfg.Verification, cfg.JWTSecret)
	if err != nil {
		return nil, fmt.Errorf("verification: %w", err)
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
	return a, nil
}

func (a *Authorization) WithJWTSecret(secret string) *Authorization {
	if secret != "" {
		a.JWTSecret = secret
	}
	return a
}

func (a *Authorization) WithAuthURL(authURL string) *Authorization {
	if authURL != "" {
		a.AuthURL = authURL
	}
	return a
}
func (a *Authorization) WithDB(db *gorm.DB) *Authorization {
	if db != nil {
		a.db = db
	}
	return a
}

func (a *Authorization) WithRedis(redis *redis.Client) *Authorization {
	if a != nil && redis != nil {
		a.redis = redis
	}
	return a
}

func (a *Authorization) WithRedisPrefix(redisPrefix string) *Authorization {
	if redisPrefix != "" {
		a.redisPrefix = redisPrefix
	}
	return a
}

func (a *Authorization) WithRedisTTL(redisTTL time.Duration) *Authorization {
	if redisTTL != 0 {
		a.redisTTL = redisTTL
	}
	return a
}

func (a *Authorization) WithCookieSessionName(cookieSessionName string) *Authorization {
	if cookieSessionName != "" {
		a.cookieSessionName = cookieSessionName
	}
	return a
}

func (a *Authorization) WithResolveUser(resolveUser func(ctx context.Context, profile Profile) (*User, bool, error)) *Authorization {
	if resolveUser != nil {
		a.resolveUser = resolveUser
	}
	return a
}
