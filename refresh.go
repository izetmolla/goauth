package goauth

import (
	"encoding/json"
	"errors"
	"net/http"

	"gorm.io/gorm"
)

// HandleRefreshToken is a middleware that conditionally modules
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
			writeJSON(w, http.StatusInternalServerError, Map{
				"error": ErrNotInitialized.Error(),
				"code":  "SERVER_ERROR",
			})
			return
		}
		if v := r.Header.Get(RefreshTokenHandlerIdentifier); v == "" || v == "no" {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		refreshToken, err := a.GetTokenFromHeader(r.Header.Get("Authorization"))
		if err != nil {
			refreshToken = bodyRefreshToken(r)
		}
		if refreshToken == "" {
			writeJSON(w, http.StatusUnauthorized, Map{
				"error": ErrMissingRefreshToken.Error(),
				"code":  "TOKEN_INVALID",
			})
			return
		}

		claims, err := a.ExtractToken(refreshToken)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, Map{
				"error": err.Error(),
				"code":  "TOKEN_INVALID",
			})
			return
		}

		session, err := a.GetSession(ctx, claims.SessionID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, ErrSessionNotFound) {
				writeJSON(w, http.StatusUnauthorized, Map{
					"error": ErrSessionNotFound.Error(),
					"code":  "UNAUTHORIZED",
				})
				return
			}
			if errors.Is(err, ErrSessionExpired) {
				writeJSON(w, http.StatusUnauthorized, Map{
					"error": ErrSessionExpired.Error(),
					"code":  "UNAUTHORIZED",
				})
				return
			}
			writeJSON(w, http.StatusInternalServerError, Map{
				"error": err.Error(),
				"code":  "SERVER_ERROR",
			})
			return
		}

		accessToken, err := a.RefreshAccessToken(claims, session)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, Map{
				"error": err.Error(),
				"code":  "SERVER_ERROR",
			})
			return
		}

		writeJSON(w, http.StatusOK, accessToken)
	})
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return ""
	}
	return body.RefreshToken
}
