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
	refreshToken, err := a.GetTokenFromHeader(r.Header.Get("Authorization"))
	if err != nil {
		refreshToken = bodyRefreshToken(r)
	}
	if refreshToken == "" {
		return nil, ErrMissingRefreshToken
	}

	claims, err := a.ExtractToken(refreshToken)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}
	if claims.SessionID == "" {
		return nil, ErrInvalidRefreshToken
	}

	ctx := r.Context()

	if err := a.ensureSessionActive(ctx, claims.SessionID); err != nil {
		return nil, err
	}

	session, err := a.GetSession(ctx, claims.SessionID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	if claims.UserID != "" && claims.UserID != session.UserID {
		return nil, ErrInvalidRefreshToken
	}

	accessToken, err := a.RefreshAccessToken(claims, session)
	if err != nil {
		return nil, err
	}

	a.SetSessionIDCookie(w, r, session.ID)

	return &CheckSessionResult{
		Tokens: Tokens{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
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

	if !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt) {
		return ErrSessionExpired
	}

	return nil
}
