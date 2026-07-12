package goauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

// Middleware wraps an http.Handler, the standard net/http middleware shape.
type Middleware func(http.Handler) http.Handler

// extractBearerToken pulls the JWT from the Authorization header (Bearer
// scheme) or, as a fallback, from the access_token query parameter.
func extractBearerToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
			return auth[7:]
		}
	}
	return r.URL.Query().Get("access_token")
}

// parseJWT validates the raw token against the configured secret and returns it.
func (a *Authorization) parseJWT(raw string) (*jwt.Token, error) {
	if raw == "" {
		return nil, errors.New("missing or malformed JWT")
	}
	token, err := jwt.Parse(raw, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(a.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid or expired JWT")
	}
	return token, nil
}

// UseAPIAuthorization returns a net/http middleware that protects API routes
// with a Bearer JWT. On success the validated token is stored on the request
// context (see GetClaims/JWTFromContext); optional roles are enforced.
func (a *Authorization) UseAPIAuthorization(opts ...AuthConfigOptions) Middleware {
	cfg := NewAuthConfigOptions(opts...)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a == nil {
				writeJSON(w, http.StatusInternalServerError, Map{
					"error": ErrNotInitialized.Error(),
					"code":  "SERVER_ERROR",
				})
				return
			}
			if IsExcludedPath(cfg.excludedPaths, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			token, err := a.parseJWT(extractBearerToken(r))
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, Map{
					"error": err.Error(),
					"code":  "UNAUTHORIZED",
				})
				return
			}
			r = r.WithContext(withJWT(r.Context(), token))

			if len(cfg.roles) > 0 {
				roles, err := a.GetRoles(r)
				if err != nil {
					writeJSON(w, http.StatusInternalServerError, Map{
						"error": err.Error(),
						"code":  "SERVER_ERROR",
					})
					return
				}
				if hasRole, _, _ := a.GetRole(cfg.roles, roles); !hasRole {
					writeJSON(w, http.StatusForbidden, Map{
						"error": fmt.Sprintf("insufficient permissions: %s", strings.Join(cfg.roles, ", ")),
						"code":  "INSUFFICIENT_PERMISSIONS",
					})
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// UseWEBAuthorization returns a net/http middleware that protects WEB
// routes with a session cookie. Missing or invalid cookies are
// redirected to the sign-in URL (preserving the original request URL
// in `redirectUrl`).
func (a *Authorization) UseWEBAuthorization(opts ...AuthConfigOptions) Middleware {
	cfg := NewAuthConfigOptions(opts...)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a == nil {
				writeJSON(w, http.StatusInternalServerError, Map{
					"error": ErrNotInitialized.Error(),
					"code":  "SERVER_ERROR",
				})
				return
			}
			if IsExcludedPath(cfg.excludedPaths, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			sessionID := readCookie(r, a.cookieSessionName)
			if sessionID == "" {
				http.Redirect(w, r, a.getAuthRedirectURL(r), http.StatusTemporaryRedirect)
				return
			}

			session, err := a.GetSession(r.Context(), sessionID)
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) ||
					errors.Is(err, ErrSessionNotFound) ||
					errors.Is(err, ErrSessionExpired) {
					http.Redirect(w, r, a.getAuthRedirectURL(r), http.StatusTemporaryRedirect)
					return
				}
				writeJSON(w, http.StatusInternalServerError, Map{
					"error": err.Error(),
					"code":  "SERVER_ERROR",
				})
				return
			}

			if len(cfg.roles) > 0 {
				userRoles := FormatRoles(session.User.Roles)
				if hasRole, _, _ := a.GetRole(cfg.roles, userRoles); !hasRole {
					writeJSON(w, http.StatusForbidden, Map{
						"error": fmt.Sprintf("insufficient permissions: %s", strings.Join(cfg.roles, ", ")),
						"code":  "INSUFFICIENT_PERMISSIONS",
					})
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// getAuthRedirectURL builds the sign-in URL with a `redirectUrl` query
// parameter pointing back at the original request, preserving the
// browser scheme.
func (a *Authorization) getAuthRedirectURL(r *http.Request) string {
	scheme := "http"
	if isSecureRequest(r) {
		scheme = "https"
	}
	original := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.RequestURI())
	return fmt.Sprintf("%s?redirectUrl=%s", a.signInRedirectURL, url.QueryEscape(original))
}
