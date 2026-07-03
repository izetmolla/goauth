package goauth

// AuthConfig controls the per-route behaviour of the API/WEB middlewares.
//
// Build it with NewAuthConfig + WithXxx options. The zero value is a
// valid no-op config: no excluded paths, no role gate.
type AuthConfig struct {
	excludedPaths []string
	roles         []string
}

// AuthConfigOptions mutates an AuthConfig in place.
type AuthConfigOptions func(*AuthConfig)

func defaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		excludedPaths: []string{},
		roles:         []string{},
	}
}

// NewAuthConfig applies the provided options on top of the defaults.
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
func (a *Authorization) WithExcludedPaths(paths []string) AuthConfigOptions {
	return func(c *AuthConfig) { c.excludedPaths = paths }
}

// WithRoles gates the route behind the given role names; the authenticated
// user must hold at least one of them.
func (a *Authorization) WithRoles(roles []string) AuthConfigOptions {
	return func(c *AuthConfig) { c.roles = roles }
}
