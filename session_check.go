package goauth

import (
	"net/http"
	"time"
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
