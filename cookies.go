package goauth

import (
	"net/http"
	"time"
)

// CookieOptions overrides individual cookie definitions. Zero values fall back
// to secure defaults derived from the request scheme.
type CookieOptions struct {
	SessionToken     *CookieOption
	CallbackURL      *CookieOption
	CSRFToken        *CookieOption
	PKCECodeVerifier *CookieOption
	State            *CookieOption
	Nonce            *CookieOption
}

// CrossSubdomainCookies returns CookieOptions that share goauth's cookies across
// every subdomain of the given parent domain, enabling single sign-on between
// e.g. example.com, manager.example.com and finance.example.com.
//
// Pass the registrable domain with a leading dot, e.g. ".example.com". Only the
// Domain is set on each cookie; the secure defaults (HttpOnly, Secure, SameSite,
// names and prefixes) are preserved. The CSRF cookie automatically uses the
// __Secure- prefix instead of __Host- (which forbids a Domain).
//
// All participating subdomains MUST use the same Secret and the same cookie
// names; for the JWT strategy the session cookie name is also the encryption
// salt, so it must match for tokens to decode everywhere.
func CrossSubdomainCookies(domain string) CookieOptions {
	d := func() *CookieOption { return &CookieOption{Domain: domain} }
	return CookieOptions{
		SessionToken:     d(),
		CallbackURL:      d(),
		CSRFToken:        d(),
		PKCECodeVerifier: d(),
		State:            d(),
		Nonce:            d(),
	}
}

// CookieOption configures a single cookie.
type CookieOption struct {
	Name     string
	HTTPOnly bool
	SameSite http.SameSite
	Path     string
	Secure   bool
	MaxAge   time.Duration
	Domain   string
}

// cookieJar resolves the concrete cookie definitions for a request, choosing
// the __Secure-/__Host- prefixed names on HTTPS, matching Auth.js conventions.
type cookieJar struct {
	secure bool
	opts   CookieOptions
}

func newCookieJar(secure bool, opts CookieOptions) *cookieJar {
	return &cookieJar{secure: secure, opts: opts}
}

func (c *cookieJar) prefix(host bool) string {
	if !c.secure {
		return ""
	}
	if host {
		return "__Host-"
	}
	return "__Secure-"
}

// def merges an optional override onto the secure base definition. Only the
// fields that are explicitly set on the override take effect, so callers can set
// just a Domain (for cross-subdomain sharing) without discarding HttpOnly,
// Secure, SameSite, etc. Booleans can only be turned on, never off, to avoid
// accidentally weakening the defaults.
func (c *cookieJar) def(override *CookieOption, base CookieOption) CookieOption {
	out := base
	if override == nil {
		return out
	}
	if override.Name != "" {
		out.Name = override.Name
	}
	if override.Path != "" {
		out.Path = override.Path
	}
	if override.Domain != "" {
		out.Domain = override.Domain
	}
	if override.SameSite != 0 {
		out.SameSite = override.SameSite
	}
	if override.MaxAge != 0 {
		out.MaxAge = override.MaxAge
	}
	out.HTTPOnly = out.HTTPOnly || override.HTTPOnly
	out.Secure = out.Secure || override.Secure
	return out
}

func (c *cookieJar) callbackURL() CookieOption {
	return c.def(c.opts.CallbackURL, CookieOption{
		Name:     c.prefix(false) + "authjs.callback-url",
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		Secure:   c.secure,
	})
}

func (c *cookieJar) csrfToken() CookieOption {
	// The CSRF token normally uses the __Host- prefix, which locks the cookie to
	// the exact host. That prefix forbids a Domain attribute, so when a Domain is
	// configured (for cross-subdomain sharing) we fall back to the __Secure-
	// prefix, which permits Domain.
	host := true
	if c.opts.CSRFToken != nil && c.opts.CSRFToken.Domain != "" {
		host = false
	}
	return c.def(c.opts.CSRFToken, CookieOption{
		Name:     c.prefix(host) + "authjs.csrf-token",
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		Secure:   c.secure,
	})
}

func (c *cookieJar) pkceCodeVerifier() CookieOption {
	return c.def(c.opts.PKCECodeVerifier, CookieOption{
		Name:     c.prefix(false) + "authjs.pkce.code_verifier",
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		Secure:   c.secure,
		MaxAge:   15 * time.Minute,
	})
}

func (c *cookieJar) state() CookieOption {
	return c.def(c.opts.State, CookieOption{
		Name:     c.prefix(false) + "authjs.state",
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		Secure:   c.secure,
		MaxAge:   15 * time.Minute,
	})
}

func (c *cookieJar) flow() CookieOption {
	return CookieOption{
		Name:     c.prefix(false) + "authjs.flow",
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		Secure:   c.secure,
		MaxAge:   15 * time.Minute,
	}
}

func (c *cookieJar) flowIntent() CookieOption {
	return CookieOption{
		Name:     c.prefix(false) + "authjs.flow-intent",
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		Secure:   c.secure,
		MaxAge:   15 * time.Minute,
	}
}

func (c *cookieJar) connectResource() CookieOption {
	return CookieOption{
		Name:     c.prefix(false) + "authjs.connect-resource",
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		Secure:   c.secure,
		MaxAge:   15 * time.Minute,
	}
}

func (c *cookieJar) nonce() CookieOption {
	return c.def(c.opts.Nonce, CookieOption{
		Name:     c.prefix(false) + "authjs.nonce",
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		Secure:   c.secure,
		MaxAge:   15 * time.Minute,
	})
}

// set writes a cookie with the given value. A non-positive maxAge other than the
// option default leaves it as a session cookie.
func setCookie(w http.ResponseWriter, opt CookieOption, value string) {
	cookie := &http.Cookie{
		Name:     opt.Name,
		Value:    value,
		Path:     opt.Path,
		Domain:   opt.Domain,
		HttpOnly: opt.HTTPOnly,
		Secure:   opt.Secure,
		SameSite: opt.SameSite,
	}
	if opt.MaxAge > 0 {
		cookie.MaxAge = int(opt.MaxAge.Seconds())
		cookie.Expires = time.Now().Add(opt.MaxAge)
	}
	http.SetCookie(w, cookie)
}

// expireOAuthFlowCookies clears transient OAuth cookies so they do not accumulate
// across repeated sign-in attempts and inflate the Cookie header.
func (c *cookieJar) expireOAuthFlowCookies(w http.ResponseWriter) {
	expireCookie(w, c.state())
	expireCookie(w, c.pkceCodeVerifier())
	expireCookie(w, c.nonce())
	expireCookie(w, c.callbackURL())
	expireCookie(w, c.flow())
	expireCookie(w, c.connectResource())
}

// expire removes a cookie by setting it to an immediately-expired empty value.
func expireCookie(w http.ResponseWriter, opt CookieOption) {
	http.SetCookie(w, &http.Cookie{
		Name:     opt.Name,
		Value:    "",
		Path:     opt.Path,
		Domain:   opt.Domain,
		HttpOnly: opt.HTTPOnly,
		Secure:   opt.Secure,
		SameSite: opt.SameSite,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// readCookie returns the value of the named cookie, or "".
func readCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// jar builds the per-request cookie jar.
func (a *Authorization) jar(secure bool) *cookieJar {
	if a == nil {
		return newCookieJar(secure, CookieOptions{})
	}
	return newCookieJar(secure, a.cookies)
}
