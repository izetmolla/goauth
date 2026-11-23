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
