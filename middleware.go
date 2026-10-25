package goauth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Middleware wraps an http.Handler, the standard net/http middleware shape.
type Middleware func(http.Handler) http.Handler

// extractBearerToken pulls the JWT from the Authorization header (Bearer
// scheme) or, as a fallback, from the access_token query parameter.
func extractBearerToken(r *http.Request) string {
	if token, ok := cutScheme(r.Header.Get("Authorization"), "Bearer "); ok {
		return token
	}
	return r.URL.Query().Get("access_token")
}

// parseJWT validates the raw token against the configured secret and returns it.
func (a *Authorization) parseJWT(raw string) (*jwt.Token, error) {
	if raw == "" {
		return nil, errors.New("missing or malformed JWT")
	}
	token, err := jwt.Parse(raw, a.keyFunc)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid or expired JWT")
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && isRefreshToken(claims) {
		return nil, errors.New("refresh token cannot be used as an access token")
	}
	return token, nil
}

// isRefreshToken reports whether claims belong to a refresh token. Tokens
// minted before the token_type claim existed are recognized by session_id,
// which only refresh tokens carry.
func isRefreshToken(claims jwt.MapClaims) bool {
	switch stringClaim(claims, "token_type") {
	case tokenTypeRefresh:
		return true
	case tokenTypeAccess:
		return false
	default:
		return stringClaim(claims, "session_id") != ""
	}
}

// UseAPIAuthorization returns a net/http middleware that protects API routes
// with a Bearer JWT. On success the validated token is stored on the request
// context (see GetClaims/JWTFromContext); optional roles are enforced.
func (a *Authorization) UseAPIAuthorization(opts ...AuthConfigOptions) Middleware {
	return a.protect(opts, func(w http.ResponseWriter, r *http.Request) (*http.Request, []string, bool) {
		token, err := a.parseJWT(extractBearerToken(r))
		if err != nil {
			writeAPIError(w, http.StatusUnauthorized, codeUnauthorized, err.Error())
			return nil, nil, false
		}
		r = r.WithContext(withJWT(r.Context(), token))
		roles, _ := a.GetRoles(r) // a missing roles claim grants no roles
		return r, roles, true
	})
}

// UseWEBAuthorization returns a net/http middleware that protects WEB
// routes with a session cookie. Missing or invalid cookies are
// redirected to the sign-in URL (preserving the original request URL
// in `redirectUrl`).
func (a *Authorization) UseWEBAuthorization(opts ...AuthConfigOptions) Middleware {
	return a.protect(opts, func(w http.ResponseWriter, r *http.Request) (*http.Request, []string, bool) {
		session, err := a.GetSession(r.Context(), a.GetSessionID(r))
		if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionExpired) {
			http.Redirect(w, r, a.getAuthRedirectURL(r), http.StatusTemporaryRedirect)
			return nil, nil, false
		}
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, codeServerError, err.Error())
			return nil, nil, false
		}
		return r, FormatRoles(session.User.Roles), true
	})
}

// protect holds the plumbing shared by the auth middlewares: the nil guard,
// excluded paths and the role gate. authenticate returns the (possibly
// updated) request and the caller's role grants, or false once it has
// written a response.
func (a *Authorization) protect(opts []AuthConfigOptions, authenticate func(http.ResponseWriter, *http.Request) (*http.Request, []string, bool)) Middleware {
	cfg := NewAuthConfigOptions(opts...)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a == nil {
				writeAPIError(w, http.StatusInternalServerError, codeServerError, ErrNotInitialized.Error())
				return
			}
			if IsExcludedPath(cfg.excludedPaths, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			r, roles, ok := authenticate(w, r)
			if !ok {
				return
			}
			if len(cfg.roles) > 0 {
				if hasRole, _, _ := a.GetRole(cfg.roles, roles); !hasRole {
					writeAPIError(w, http.StatusForbidden, codeInsufficientPermissions, "insufficient permissions: "+strings.Join(cfg.roles, ", "))
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
	original := requestScheme(r) + "://" + r.Host + r.URL.RequestURI()
	return a.signInRedirectURL + "?redirectUrl=" + url.QueryEscape(original)
}
