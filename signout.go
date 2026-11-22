package goauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// RevokeSession signs one session out: its refresh token and session cookie
// stop working on the next request, and its Redis copy is removed. Access
// tokens already issued stay valid until they expire. Revoking an unknown or
// already revoked session is not an error.
func (a *Authorization) RevokeSession(ctx context.Context, sessionID string) error {
	if a == nil || a.db == nil {
		return ErrNotInitialized
	}
	if sessionID == "" {
		return nil
	}
	err := a.db.WithContext(ctx).Table(a.sessionsTable()).
		Where("id = ? AND is_deleted = ?", sessionID, false).
		Updates(map[string]any{"is_deleted": true, "updated_at": time.Now().UTC()}).Error
	if err != nil {
		return err
	}
	a.deleteSessionFromRedis(ctx, sessionID)
	return nil
}

// RevokeUserSessions signs a user out on every device, for example after a
// password change or when the account is disabled.
func (a *Authorization) RevokeUserSessions(ctx context.Context, userID string) error {
	if a == nil || a.db == nil {
		return ErrNotInitialized
	}
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	return a.revokeUserSessions(ctx, userID)
}

// SignOut revokes the request's session and expires the session cookie. The
// session is taken from the session cookie or, for API clients, from a
// refresh token in the Authorization header or a JSON body
// {"refresh_token": "..."}. A request without a session only clears the
// cookie.
func (a *Authorization) SignOut(w http.ResponseWriter, r *http.Request) error {
	if a == nil {
		return ErrNotInitialized
	}
	_, secure, err := a.origin(r)
	if err != nil {
		secure = isSecureRequest(r)
	}
	expireCookie(w, a.sessionCookie(secure))

	sessionID := a.GetSessionID(r)
	if sessionID == "" {
		raw, err := a.GetTokenFromHeader(r.Header.Get("Authorization"))
		if err != nil {
			raw = bodyRefreshToken(r)
		}
		if claims, err := a.ExtractToken(raw); err == nil {
			sessionID = claims.SessionID
		}
	}
	return a.RevokeSession(r.Context(), sessionID)
}

// HandleSignOut implements POST {base}/signout: it calls SignOut and answers
// 204 No Content, or 500 when the session could not be revoked. Disable it
// with Endpoints.DisableSignOut.
func (a *Authorization) HandleSignOut(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		writeAPIError(w, http.StatusInternalServerError, codeServerError, ErrNotInitialized.Error())
		return
	}
	if a.endpoints.DisableSignOut {
		notFound(w)
		return
	}
	if err := a.SignOut(w, r); err != nil {
		writeAPIError(w, http.StatusInternalServerError, codeServerError, msgSomethingWrong)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
