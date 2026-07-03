package goauth

import (
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

func defaultConfig() *Config {
	return &Config{
		JWTSecret:            "",
		DB:                   nil,
		Redis:                nil,
		AuthURL:              "localhost",
		AccessTokenDuration:  DefaultAccessTokenDuration,
		RefreshTokenDuration: DefaultRefreshTokenDuration,
		RedisPrefix:          DefaultRedisPrefix,
		UserTableName:        DefaultUserTableName,
		SessionTableName:     DefaultSessionTableName,
		RedisTTL:             DefaultRedisTTL,
		SigningMethod:        DefaultSigningMethodHMAC,
		SignInRedirectURL:    DefaultSignInRedirectURL,
		CookieSessionName:    DefaultCookieSessionName,
		Providers:            []Provider{},
		Cookies:              &CookieOptions{},
		ResolveUser:          nil,
	}
}
func New(config *Config, opts ...ConfigFunc) (*Authorization, error) {
	if config == nil {
		return nil, errors.New("config is required")
	}
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	cookies := CookieOptions{}
	if cfg.Cookies != nil {
		cookies = *cfg.Cookies
	}
	auth := &Authorization{
		JWTSecret:            cfg.JWTSecret,
		db:                   config.DB,
		redis:                config.Redis,
		redisPrefix:          cfg.RedisPrefix,
		userTableName:        cfg.UserTableName,
		sessionTableName:     cfg.SessionTableName,
		redisTTL:             cfg.RedisTTL,
		accessTokenDuration:  cfg.AccessTokenDuration,
		refreshTokenDuration: cfg.RefreshTokenDuration,
		signInRedirectURL:    cfg.SignInRedirectURL,
		cookieSessionName:    cfg.CookieSessionName,
		providers:            config.Providers,
		cookies:              cookies,
		AuthURL:              config.AuthURL,
		signingMethod:        cfg.SigningMethod,
	}
	if config.SigningMethod != "" {
		auth.signingMethod = config.SigningMethod
	}
	if cfg.JWTSecret == "" {
		if config.JWTSecret == "" {
			return nil, errors.New("JWTSecret is required")
		}
		auth.JWTSecret = config.JWTSecret
	}

	if auth.db == nil {
		if config.DB == nil {
			return nil, errors.New("db is required")
		}
		auth.db = config.DB
	}
	if auth.redis == nil {
		auth.redis = config.Redis
	}
	if config.Cookies != nil {
		auth.cookies = *config.Cookies
	}
	if config.ResolveUser != nil {
		auth.resolveUser = config.ResolveUser
	} else if cfg.ResolveUser != nil {
		auth.resolveUser = cfg.ResolveUser
	}
	if config.OnProviderConnect != nil {
		auth.onProviderConnect = config.OnProviderConnect
	} else if cfg.OnProviderConnect != nil {
		auth.onProviderConnect = cfg.OnProviderConnect
	}

	return auth, nil
}

func (a *Authorization) WithJWTSecret(JWTSecret string) *Authorization {
	if JWTSecret != "" {
		a.JWTSecret = JWTSecret
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
