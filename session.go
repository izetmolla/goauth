package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"uuid"

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

	// LoggedBy is the admin user id when this session was created via login_as.
	LoggedBy *string `json:"logged_by,omitempty" gorm:"column:logged_by;size:64"`

	Account JSONBAny `json:"account" gorm:"type:jsonb;default:null"`

	ExpiresAt time.Time `json:"expires_at"`
	IsDeleted bool      `json:"is_deleted" gorm:"default:false"`

	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// BeforeCreate sets the session id before creation, so ids are generated
// the same way on every database. The id is a bearer secret (it is the WEB
// session cookie value), so it is always a random version 4 UUID (122
// random bits) and never a time-ordered v7, which would leak the creation
// time and carry less entropy.
func (s *Session) BeforeCreate(*gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.NewV4().String()
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
	// The database is the source of truth for every lookup: a signed-out or
	// expired session, a deleted user, or a revoked role must take effect on
	// the very next request. Reading Redis first could not skip that query,
	// so the lookup goes straight to the database and Redis is kept as a
	// write-through copy for anything that reads it.
	session, err := a.loadSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionExpired) {
			a.deleteSessionFromRedis(ctx, sessionID)
		}
		return nil, err
	}
	if a.redis != nil {
		_ = a.SetSessionToRedis(ctx, &SessionData{
			ID:     session.ID,
			UserID: session.UserID,
			Roles:  session.User.Roles,
		})
	}
	return session, nil
}

// sessionRow is a session row joined with its user's id and roles.
type sessionRow struct {
	Session   `gorm:"embedded"`
	JoinedID  *string    `gorm:"column:goauth_user_id"`
	JoinedRls JSONBArray `gorm:"column:goauth_user_roles"`
}

// loadSession fetches a session and its user's roles in one round trip. A
// missing, signed-out or expired session, or a session whose user no longer
// exists, yields ErrSessionNotFound / ErrSessionExpired.
func (a *Authorization) loadSession(ctx context.Context, sessionID string) (*Session, error) {
	var row sessionRow
	// Portable across GORM drivers (PostgreSQL, MySQL, SQLite, SQL Server,
	// Oracle): table aliases are written without AS (Oracle rejects it),
	// identifiers are quoted by the active dialect, row limiting is left to
	// Take, and expiry is checked in Go rather than with database time
	// functions.
	err := a.db.WithContext(ctx).
		Unscoped(). // soft-delete filter is written out below, against the alias
		Table(a.quoteIdent(a.sessionsTable())+" s").
		Select("s.*, u.id AS goauth_user_id, u.roles AS goauth_user_roles").
		Joins("LEFT JOIN "+a.quoteIdent(a.userTableName)+" u ON u.id = s.user_id").
		Where("s.id = ? AND s.is_deleted = ? AND s.deleted_at IS NULL", sessionID, false).
		// An explicit, qualified order: SQL Server needs one for its
		// OFFSET/FETCH row limit, and GORM's default ("id") would be
		// ambiguous between the two joined tables.
		Order("s.id").
		Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := sessionUsable(&row.Session); err != nil {
		return nil, err
	}
	if row.JoinedID == nil {
		return nil, ErrSessionNotFound // the user was deleted
	}
	session := row.Session
	session.User = User{ID: *row.JoinedID, Roles: row.JoinedRls}
	return &session, nil
}

// quoteIdent quotes a configured table name for the active dialect, so
// names such as "user" (reserved in PostgreSQL) still work in raw SQL.
func (a *Authorization) quoteIdent(name string) string {
	var b strings.Builder
	a.db.QuoteTo(&b, name)
	return b.String()
}

// deleteSessionFromRedis drops a session's cache entry. Failures are ignored:
// the database check on the next request still rejects the session.
func (a *Authorization) deleteSessionFromRedis(ctx context.Context, sessionID string) {
	if a == nil || a.redis == nil || sessionID == "" {
		return
	}
	_ = a.redis.Del(ctx, buildRedisKey(a.redisPrefix, sessionID)).Err()
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

	refreshTokenDuration, err := a.refreshTokenTTL()
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
	if o.loggedBy != nil && o.loggedBy.ID != "" {
		id := o.loggedBy.ID
		session.LoggedBy = &id
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
	if d, err := a.refreshTokenTTL(); err == nil {
		maxAge = d
	}
	jar := a.jar(secure)
	return jar.def(a.cookies.SessionToken, jar.base(a.cookieSessionName, maxAge))
}
