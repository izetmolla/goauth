package goauth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
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

// parseAccessToken verifies the raw token (signature, configured algorithm,
// required expiry) and rejects refresh tokens.
func (a *Authorization) parseAccessToken(raw string) (*apiPrincipal, error) {
	if raw == "" {
		return nil, errors.New("missing or malformed JWT")
	}
	claims := &accessClaims{}
	token, err := a.jwtParser().ParseWithClaims(raw, claims, a.keyFunc)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid or expired JWT")
	}
	if claims.isRefresh() {
		return nil, errors.New("refresh token cannot be used as an access token")
	}
	return &apiPrincipal{token: token, claims: claims}, nil
}

// UseAPIAuthorization returns a net/http middleware that protects API routes
// with a Bearer JWT. On success the validated token is stored on the request
// context (see GetClaims/JWTFromContext); optional roles are enforced.
//
// Pass WithReauthorize() so browser clients that only have the WEB session
// cookie (cross-subdomain SSO) can bootstrap an access token via the cra
// header instead of receiving 401.
func (a *Authorization) UseAPIAuthorization(opts ...AuthConfigOptions) Middleware {
	cfg := NewAuthConfigOptions(opts...)
	return a.protectConfig(cfg, func(w http.ResponseWriter, r *http.Request) (*http.Request, func() []string, bool) {
		p, err := a.parseAccessToken(extractBearerToken(r))
		if err != nil {
			if cfg.reauthorize && wantsReauthorize(r) && a.writeReauthorize(w, r, cfg) {
				return nil, nil, false
			}
			writeAPIError(w, http.StatusUnauthorized, codeUnauthorized, err.Error())
			return nil, nil, false
		}
		roles := func() []string {
			grants, _ := p.Roles() // a missing roles claim grants no roles
			return grants
		}
		return r.WithContext(withPrincipal(r.Context(), p)), roles, true
	})
}

// UseWEBAuthorization returns a net/http middleware that protects WEB
// routes with a session cookie. Missing or invalid cookies are
// redirected to the sign-in URL (preserving the original request URL
// in `redirectUrl`). On success the principal is stored on the request
// context, so GetAuthDataWEB and AuthDataFromContext need no second lookup.
func (a *Authorization) UseWEBAuthorization(opts ...AuthConfigOptions) Middleware {
	return a.protect(opts, func(w http.ResponseWriter, r *http.Request) (*http.Request, func() []string, bool) {
		session, err := a.GetSession(r.Context(), a.GetSessionID(r))
		if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionExpired) {
			http.Redirect(w, r, a.getAuthRedirectURL(r), http.StatusTemporaryRedirect)
			return nil, nil, false
		}
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, codeServerError, err.Error())
			return nil, nil, false
		}
		data := AuthData{SessionID: session.ID, UserID: session.UserID, Roles: FormatRoles(session.User.Roles)}
		return r.WithContext(withAuthData(r.Context(), data)), func() []string { return data.Roles }, true
	})
}

// protect holds the plumbing shared by the auth middlewares: the nil guard,
// excluded paths and the role gate. authenticate returns the (possibly
// updated) request and a function yielding the caller's role grants, which
// is only called when the route has a role gate, or false once it has
// written a response.
func (a *Authorization) protect(opts []AuthConfigOptions, authenticate func(http.ResponseWriter, *http.Request) (*http.Request, func() []string, bool)) Middleware {
	return a.protectConfig(NewAuthConfigOptions(opts...), authenticate)
}

func (a *Authorization) protectConfig(cfg *AuthConfig, authenticate func(http.ResponseWriter, *http.Request) (*http.Request, func() []string, bool)) Middleware {
	if cfg == nil {
		cfg = defaultAuthConfig()
	}
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
				if hasRole, _, _ := a.GetRole(cfg.roles, roles()); !hasRole {
					writeRoleDenied(w, r, cfg)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// wantsReauthorize reports whether the client opted into the cra bootstrap
// handshake (packages/network sends cra=t when localStorage has no tokens).
func wantsReauthorize(r *http.Request) bool {
	if r == nil {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(r.Header.Get(ReauthorizeHandlerIdentifier)))
	switch v {
	case "", "0", "f", "false", "no", "off":
		return false
	default:
		return true
	}
}

// writeReauthorize mints an access+refresh pair from the WEB session cookie
// and writes the {reauthorize, session_id, user, tokens} payload expected by
// packages/network interceptors. Reports false when no usable cookie/session
// exists so the caller can fall through to a normal 401.
//
// Unlike the OAuth callback (which may blank refresh under
// KeepRefreshTokenServerSide), cra bootstrap always returns both tokens so
// clients that need Bearer-based refresh have a credential after SSO.
func (a *Authorization) writeReauthorize(w http.ResponseWriter, r *http.Request, cfg *AuthConfig) bool {
	if a == nil || r == nil {
		return false
	}
	sessionID := a.GetSessionID(r)
	if sessionID == "" {
		return false
	}
	session, err := a.GetSession(r.Context(), sessionID)
	if err != nil || session == nil {
		return false
	}

	opts := []AuthorizeOptionsFunc{
		a.WithUserID(session.UserID),
		a.WithUserRoles(session.User.Roles),
		a.WithContext(r.Context()),
	}
	if session.LoggedBy != nil && *session.LoggedBy != "" {
		opts = append(opts, a.WithLoggedBy(&LoggedBy{ID: *session.LoggedBy}))
	}
	accessToken, refreshToken, err := a.SignTokenPair(NewAuthorizeOptions(opts...), session.ID)
	if err != nil || accessToken == "" || refreshToken == "" {
		return false
	}

	user := FormatUser(&session.User)
	if cfg != nil && cfg.reauthorizeUser != nil {
		custom, err := cfg.reauthorizeUser(r.Context(), session)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, codeServerError, err.Error())
			return true
		}
		if custom != nil {
			user = custom
		}
	}

	writeJSON(w, http.StatusOK, Map{
		"reauthorize": true,
		"session_id":  session.ID,
		"user":        user,
		"tokens": Tokens{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	})
	return true
}

// getAuthRedirectURL builds the sign-in URL with a redirectUrl query
// parameter pointing back at the page the user asked for.
//
// The sign-in target is SignInRedirectURL. When that value is relative and
// AuthURL is set, it is resolved against AuthURL so a central auth host
// (AUTH_URL=https://auth.example.com) receives anonymous users from other
// apps. Absolute SignInRedirectURL values are used as is.
//
// redirectUrl is always the incoming request (honoring X-Forwarded-Host /
// X-Forwarded-Proto), not AuthURL — AuthURL may be the auth portal, while
// the protected page lives on another origin.
func (a *Authorization) getAuthRedirectURL(r *http.Request) string {
	signIn := a.absoluteSignInURL()
	sep := "?"
	if strings.Contains(signIn, "?") {
		sep = "&"
	}
	return signIn + sep + "redirectUrl=" + url.QueryEscape(a.protectedRequestURL(r))
}

// absoluteSignInURL is the Location target for anonymous WEB users.
func (a *Authorization) absoluteSignInURL() string {
	path := a.signInRedirectURL
	if path == "" {
		path = DefaultSignInRedirectURL
	}
	if isAbsoluteHTTPURL(path) {
		return path
	}
	if a == nil || a.AuthURL == "" {
		return path
	}
	origin, _, err := parseOriginURL(a.AuthURL)
	if err != nil || origin == "" {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return origin + path
}

// protectedRequestURL is the URL UseWEBAuthorization sends back in
// redirectUrl: scheme + host of the request being gated, plus its path.
// X-Forwarded-Host / X-Forwarded-Proto are honored only when the TCP peer is
// a Config.TrustedProxies entry, matching trustedClientIP.
func (a *Authorization) protectedRequestURL(r *http.Request) string {
	host := r.Host
	scheme := schemeHTTP
	if r.TLS != nil {
		scheme = schemeHTTPS
	}
	if a != nil && a.peerIsTrustedProxy(r) {
		if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
			host = fwd
		}
		scheme = requestScheme(r)
	}
	return scheme + "://" + host + r.URL.RequestURI()
}

func isAbsoluteHTTPURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && u.Host != "" && (u.Scheme == schemeHTTP || u.Scheme == schemeHTTPS)
}
