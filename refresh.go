package goauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// HandleRefreshToken is a middleware that conditionally handles
// refresh-token requests. The request is only handled when the client
// opts in by setting the RefreshTokenHandlerIdentifier header; every
// other request is forwarded to the next handler.
//
// On success the response body is the new access token; on failure a
// JSON envelope with an error message and machine-readable code is
// returned.
func (a *Authorization) HandleRefreshToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a == nil {
			writeAPIError(w, http.StatusInternalServerError, codeServerError, ErrNotInitialized.Error())
			return
		}
		if v := r.Header.Get(RefreshTokenHandlerIdentifier); v == "" || v == "no" {
			next.ServeHTTP(w, r)
			return
		}

		_, accessToken, _, err := a.refreshFromRequest(r)
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, accessToken)
		case errors.Is(err, ErrMissingRefreshToken), errors.Is(err, ErrInvalidRefreshToken):
			writeAPIError(w, http.StatusUnauthorized, codeTokenInvalid, err.Error())
		case errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrSessionExpired):
			writeAPIError(w, http.StatusUnauthorized, codeUnauthorized, err.Error())
		default:
			writeAPIError(w, http.StatusInternalServerError, codeServerError, err.Error())
		}
	})
}

// refreshFromRequest validates the request's refresh token (Authorization
// header, else JSON body) and its session, then issues a new access token.
func (a *Authorization) refreshFromRequest(r *http.Request) (refreshToken, accessToken string, session *Session, err error) {
	refreshToken, err = a.GetTokenFromHeader(r.Header.Get("Authorization"))
	if err != nil {
		refreshToken = bodyRefreshToken(r)
	}
	if refreshToken == "" {
		return "", "", nil, ErrMissingRefreshToken
	}
	claims, err := a.ExtractToken(refreshToken)
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: %w", ErrInvalidRefreshToken, err)
	}
	if session, err = a.GetSession(r.Context(), claims.SessionID); err != nil {
		return "", "", nil, err
	}
	if claims.UserID != "" && claims.UserID != session.UserID {
		return "", "", nil, ErrInvalidRefreshToken
	}
	accessToken, err = a.RefreshAccessToken(claims, session)
	return refreshToken, accessToken, session, err
}

// bodyRefreshToken pulls a refresh token out of the JSON body. Errors
// are swallowed: an absent body simply means "no fallback available".
func bodyRefreshToken(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		return ""
	}
	return body.RefreshToken
}
