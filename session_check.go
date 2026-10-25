package goauth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"gorm.io/gorm"
)

// CheckSessionResult mirrors a successful sign-in payload without creating a session.
type CheckSessionResult struct {
	Tokens    Tokens
	SessionID string
	UserID    string
}

// CheckSession validates an existing refresh token and session, refreshes the
// access token with up-to-date roles, and sets the WEB session cookie.
func (a *Authorization) CheckSession(w http.ResponseWriter, r *http.Request) (*CheckSessionResult, error) {
	if a == nil {
		return nil, ErrNotInitialized
	}
	refreshToken, accessToken, session, err := a.refreshFromRequest(r)
	if err != nil {
		return nil, err
	}
	a.SetSessionIDCookie(w, r, session.ID)
	return &CheckSessionResult{
		Tokens:    Tokens{AccessToken: accessToken, RefreshToken: refreshToken},
		SessionID: session.ID,
		UserID:    session.UserID,
	}, nil
}

func (a *Authorization) ensureSessionActive(ctx context.Context, sessionID string) error {
	if a.db == nil {
		return errors.New("db manager is not initialized")
	}

	var session Session
	err := a.db.WithContext(ctx).
		Table(a.sessionsTable()).
		Where("id = ? AND is_deleted = ?", sessionID, false).
		First(&session).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrSessionNotFound
		}
		return err
	}

	return sessionUsable(&session)
}

// sessionUsable reports whether a loaded session row may still authenticate
// requests: it must not be soft-deleted and must not be past its expiry.
func sessionUsable(s *Session) error {
	if s == nil || s.IsDeleted {
		return ErrSessionNotFound
	}
	if !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt) {
		return ErrSessionExpired
	}
	return nil
}
