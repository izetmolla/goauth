package goauth

import (
	"cmp"
	"context"
	"errors"
	"time"

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

	var cookies CookieOptions
	if cfg.Cookies != nil {
		cookies = *cfg.Cookies
	}
	return &Authorization{
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
	}, nil
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
