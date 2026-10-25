package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type SessionData struct {
	ID     string     `json:"id"`
	UserID string     `json:"user_id"`
	Roles  JSONBArray `json:"roles"`
}

type SessionType string

const (
	SessionTypeSignIn SessionType = "sign_in"
	SessionTypeOAuth  SessionType = "oauth"
)

type Session struct {
	ID     string      `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID string      `json:"user_id" gorm:"type:uuid;default:null"`
	User   User        `json:"user" gorm:"-"`
	Type   SessionType `json:"type" gorm:"type:varchar(255);default:'sign_in';"`

	IPAddress string `json:"ip_address" gorm:"size:50;"`
	UserAgent string `json:"user_agent" gorm:"size:255;"`
	Method    string `json:"method" gorm:"size:50;default:'credentials';"`

	Account JSONBAny `json:"account" gorm:"type:jsonb;default:null"`

	ExpiresAt time.Time `json:"expires_at"`
	IsDeleted bool      `json:"is_deleted" gorm:"default:false"`

	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// BeforeCreate sets a UUID for the user before creation.
// This ensures consistent ID generation across different database systems.
func (s *Session) BeforeCreate(*gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

// --- Session & user lookup ------------------------------------------------

// GetSession loads a session (and its user) by id, using the Redis cache
// when available. A missing id, session or user yields ErrSessionNotFound.
func (a *Authorization) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	if sessionID == "" {
		return nil, ErrSessionNotFound
	}
	session, err := a.GetSessionFromDB(ctx, sessionID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrSessionNotFound
	}
	return session, err
}

func (a *Authorization) GetSessionFromDB(ctx context.Context, sessionID string) (*Session, error) {
	if a == nil || a.db == nil {
		return nil, errors.New("db manager is not initialized")
	}
	if sessionID == "" {
		return nil, errors.New("session ID cannot be empty")
	}
	if a.redis != nil {
		session, err := a.GetSessionFromRedis(ctx, sessionID)
		if err == nil {
			if activeErr := a.ensureSessionActive(ctx, sessionID); activeErr != nil {
				return nil, activeErr
			}
			roles := session.Roles
			if fresh, err := a.getUserRolesFromDB(ctx, session.UserID); err == nil && len(fresh) > 0 {
				roles = fresh
				_ = a.SetSessionToRedis(ctx, &SessionData{
					ID:     session.ID,
					UserID: session.UserID,
					Roles:  roles,
				})
			}
			return &Session{
				ID:     session.ID,
				UserID: session.UserID,
				User: User{
					ID:    session.UserID,
					Roles: roles,
				},
			}, nil
		}
	}
	var session Session
	if err := a.db.
		WithContext(ctx).
		Table(a.sessionsTable()).
		Where("id = ? AND is_deleted = ?", sessionID, false).
		First(&session).Error; err != nil {
		return nil, err
	}
	// The Redis path validates liveness via ensureSessionActive; the DB
	// fallback must apply the same rules or logged-out/expired sessions
	// keep authenticating.
	if err := sessionUsable(&session); err != nil {
		return nil, err
	}
	if err := a.db.WithContext(ctx).
		Table(a.userTableName).
		Select("id", "roles").
		Where("id = ?", session.UserID).
		First(&session.User).Error; err != nil {
		return nil, err
	}

	if a.redis != nil {
		_ = a.SetSessionToRedis(ctx, &SessionData{
			ID:     session.ID,
			UserID: session.UserID,
			Roles:  session.User.Roles,
		})
	}
	return &session, nil
}

// GetSessionFromRedis retrieves session data from Redis cache.
//
// Parameters:
//   - sessionID: The unique session identifier
//
// Returns:
//   - *SessionData: Session data if found
//   - error: Error if session not found or Redis error occurs
func (a *Authorization) GetSessionFromRedis(ctx context.Context, sessionID string) (*SessionData, error) {
	if a == nil || a.redis == nil {
		return nil, errors.New("redis is not configured")
	}
	if sessionID == "" {
		return nil, errors.New("session ID cannot be empty")
	}

	redisKey := buildRedisKey(a.redisPrefix, sessionID)
	data, err := a.redis.Get(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, redis.Nil
		}
		return nil, err
	}

	return deserializeSessionData([]byte(data))
}

// SetSessionToRedis stores session data in Redis cache.
//
// Parameters:
//   - ctx: The context
//   - session: The session data to store
//
// Returns:
//   - error: Error if storage fails
func (a *Authorization) SetSessionToRedis(ctx context.Context, session *SessionData) error {
	if a == nil || a.redis == nil {
		return errors.New("redis is not configured")
	}
	if err := validateSessionData(session); err != nil {
		return err
	}

	redisKey := buildRedisKey(a.redisPrefix, session.ID)
	data, err := serializeSessionData(session)
	if err != nil {
		return err
	}

	if err := a.redis.Set(ctx, redisKey, data, a.redisTTL).Err(); err != nil {
		return err
	}

	return nil
}

// CreateSession persists a new session row.
func (a *Authorization) CreateSession(o *AuthorizeOptions) (string, error) {
	if a == nil {
		return "", errors.New("authorization is not initialized")
	}
	if a.db == nil {
		return "", errors.New("db manager is not initialized")
	}
	if o == nil {
		return "", errors.New("authorize options are required")
	}

	refreshTokenDuration, err := ParseCustomDuration(a.refreshTokenDuration, DefaultRefreshTokenDuration)
	if err != nil {
		return "", fmt.Errorf("parse refresh token duration: %w", err)
	}

	session := Session{
		UserID:    o.userID,
		IPAddress: o.ipAddress,
		UserAgent: o.userAgent,
		Method:    o.method,
		ExpiresAt: time.Now().Add(refreshTokenDuration),
	}
	if o.account != nil {
		session.Account = accountToJSONB(o.account)
	}
	if err := a.db.WithContext(o.ctx).Table(a.sessionsTable()).Create(&session).Error; err != nil {
		return "", err
	}
	return session.ID, nil
}

func (a *Authorization) sessionsTable() string {
	if a != nil && a.sessionTableName != "" {
		return a.sessionTableName
	}
	return DefaultSessionTableName
}

func accountToJSONB(account *Account) JSONBAny {
	if account == nil {
		return nil
	}
	payload, err := json.Marshal(account)
	if err != nil {
		return nil
	}
	var out JSONBAny
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil
	}
	return out
}

// GetSessionID returns the session id carried by the request's session
// cookie, or "" when absent.
func (a *Authorization) GetSessionID(r *http.Request) string {
	return readCookie(r, a.sessionCookie(false).Name)
}

// SetSessionIDCookie writes the WEB session cookie used by UseWEBAuthorization.
func (a *Authorization) SetSessionIDCookie(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		return
	}
	_, secure, err := a.origin(r)
	if err != nil {
		secure = isSecureRequest(r)
	}
	setCookie(w, a.sessionCookie(secure), sessionID)
}

// sessionCookie resolves the WEB session cookie definition. It honors
// CookieOptions.SessionToken so CrossSubdomainCookies can share the session
// across subdomains. The name carries no __Secure- prefix, so it is stable
// regardless of scheme.
func (a *Authorization) sessionCookie(secure bool) CookieOption {
	maxAge := 365 * 24 * time.Hour
	if d, err := ParseCustomDuration(a.refreshTokenDuration, DefaultRefreshTokenDuration); err == nil {
		maxAge = d
	}
	jar := a.jar(secure)
	return jar.def(a.cookies.SessionToken, jar.base(a.cookieSessionName, maxAge))
}
