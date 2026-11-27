package goauth

import "context"

// ReauthorizeUserFunc builds the user object returned in a cra reauthorize
// payload. The default is FormatUser(&session.User) (id + roles).
type ReauthorizeUserFunc func(ctx context.Context, session *Session) (any, error)

// AuthConfig controls the per-route behavior of the API/WEB middlewares.
//
// Build it with NewAuthConfig + WithXxx options. The zero value is a
// valid no-op config: no excluded paths, no role gate.
type AuthConfig struct {
	excludedPaths []string
	roles         []string
	// reauthorize enables the cra header handshake on UseAPIAuthorization.
	reauthorize bool
	// reauthorizeUser customizes the user field of the reauthorize payload.
	reauthorizeUser ReauthorizeUserFunc
	// render customizes the response when a role gate denies access.
	render *RenderOptions
}

// RenderOptions customizes the HTTP response written when WithRoles denies
// an authenticated caller. Nil / zero WithRender keeps the default JSON 403.
//
// Precedence: RedirectURL > HTML > Body > Message > default JSON message.
type RenderOptions struct {
	// Status is the HTTP status for non-redirect responses (default 403).
	// For RedirectURL, defaults to 302 when unset or below 300.
	Status int
	// Message replaces the default JSON error string in the
	// {"error","code":"INSUFFICIENT_PERMISSIONS"} envelope.
	Message string
	// Body is a raw response body (text/plain unless ContentType is set).
	Body string
	// HTML is a text/html body and takes precedence over Body.
	HTML string
	// ContentType overrides the Content-Type for Body responses.
	ContentType string
	// RedirectURL issues an HTTP redirect and takes precedence over bodies/messages.
	RedirectURL string
}

// AuthConfigOptions mutates an AuthConfig in place.
type AuthConfigOptions func(*AuthConfig)

func defaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		excludedPaths: []string{},
		roles:         []string{},
	}
}

// NewAuthConfigOptions applies the provided options on top of the defaults.
func NewAuthConfigOptions(opts ...AuthConfigOptions) *AuthConfig {
	cfg := defaultAuthConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	return cfg
}

// WithExcludedPaths whitelists path prefixes that should not require auth.
func WithExcludedPaths(paths []string) AuthConfigOptions {
	return func(c *AuthConfig) { c.excludedPaths = paths }
}

// WithExcludedPaths whitelists path prefixes that should not require auth.
func (a *Authorization) WithExcludedPaths(paths []string) AuthConfigOptions {
	return WithExcludedPaths(paths)
}

// WithRoles gates the route behind the given role names; the authenticated
// user must hold at least one of them.
func WithRoles(roles []string) AuthConfigOptions {
	return func(c *AuthConfig) { c.roles = roles }
}

// WithRoles gates the route behind the given role names; the authenticated
// user must hold at least one of them.
func (a *Authorization) WithRoles(roles []string) AuthConfigOptions {
	return WithRoles(roles)
}

// WithRender customizes the response when a WithRoles gate denies access.
// See RenderOptions for field precedence. Optional — omit for default JSON 403.
func WithRender(opts RenderOptions) AuthConfigOptions {
	return func(c *AuthConfig) {
		copy := opts
		c.render = &copy
	}
}

// WithRender customizes the response when a WithRoles gate denies access.
func (a *Authorization) WithRender(opts RenderOptions) AuthConfigOptions {
	return WithRender(opts)
}

// WithReauthorize enables the cra header handshake used by browser clients
// (e.g. @workspace/network): when the request has no usable Bearer access
// token but presents a valid WEB session cookie, UseAPIAuthorization
// responds with {reauthorize, session_id, user, tokens} instead of 401 so
// the SPA can bootstrap its store after cross-subdomain SSO.
func WithReauthorize() AuthConfigOptions {
	return func(c *AuthConfig) { c.reauthorize = true }
}

// WithReauthorize enables the cra header handshake on UseAPIAuthorization.
func (a *Authorization) WithReauthorize() AuthConfigOptions {
	return WithReauthorize()
}

// WithReauthorizeUser enables reauthorize and sets a custom user builder for
// the payload (for example to include email/name from the users table).
func WithReauthorizeUser(fn ReauthorizeUserFunc) AuthConfigOptions {
	return func(c *AuthConfig) {
		c.reauthorize = true
		c.reauthorizeUser = fn
	}
}

// WithReauthorizeUser enables reauthorize and sets a custom user builder.
func (a *Authorization) WithReauthorizeUser(fn ReauthorizeUserFunc) AuthConfigOptions {
	return WithReauthorizeUser(fn)
}
