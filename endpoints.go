package goauth

import (
	"fmt"
	"net/http"
	"regexp"
)

// EndpointOptions switches built-in endpoints on or off. The zero value is
// the default: sign-in (OAuth, credentials, the sign-in page) is on;
// sign-up is off. Password reset, email confirmation and one-time-code
// sign-in are switched on in Config.Verification.
type EndpointOptions struct {
	// DisableProviders removes GET {base}/providers.
	DisableProviders bool
	// DisablePages removes every built-in HTML page (sign-in, register,
	// forgot password, one-time code, verify email) and their assets. The
	// JSON endpoints keep working for your own UI.
	DisablePages bool
	// DisableCredentials stops credentials providers from signing users in
	// (POST {base}/provider/{id}) and hides the password form.
	DisableCredentials bool
	// EnableRegister turns on sign-up: GET {base}/register and
	// POST {base}/provider/{id}/register, for credentials providers that
	// set Register. Off by default.
	EnableRegister bool
	// DisableCSRF removes GET {base}/csrf. The built-in pages still issue
	// their own CSRF token; this only removes the JSON endpoint used by SPAs.
	DisableCSRF bool
}

// UIOptions brands the built-in sign-in page. Every field is optional.
type UIOptions struct {
	// AppName is shown in the heading ("Sign in to <AppName>") and title.
	AppName string
	// LogoURL is an image shown above the heading.
	LogoURL string
	// AccentColor is the CSS color of primary buttons and focus rings, e.g.
	// "#6d28d9" or "oklch(0.55 0.2 270)".
	AccentColor string
	// TermsURL and PrivacyURL add links under the form.
	TermsURL   string
	PrivacyURL string
	// DefaultRedirect is where users land after signing in when the page
	// was opened without a redirectUrl. Must be a same-origin path. Default "/".
	DefaultRedirect string
}

// cssColor accepts hex colors, CSS color functions and named colors, which
// keeps AccentColor from smuggling other CSS into the page.
var cssColor = regexp.MustCompile(`^(#[0-9a-fA-F]{3,8}|(rgb|rgba|hsl|hsla|hwb|lab|lch|oklab|oklch)\([0-9a-z.,%/\s+-]{1,80}\)|[a-zA-Z]{3,30})$`)

func (u UIOptions) validate() error {
	if u.AccentColor != "" && !cssColor.MatchString(u.AccentColor) {
		return fmt.Errorf("invalid UI.AccentColor %q: use a CSS color such as #6d28d9", u.AccentColor)
	}
	if u.DefaultRedirect != "" && sanitizeRedirectPath(u.DefaultRedirect) == "" {
		return fmt.Errorf("invalid UI.DefaultRedirect %q: use a same-origin path such as /dashboard", u.DefaultRedirect)
	}
	return nil
}

// signInPagePath is where users are sent to sign in: the built-in page when
// pages are enabled, otherwise Config.SignInRedirectURL.
func (a *Authorization) signInPagePath() string {
	if a.endpoints.DisablePages {
		return a.signInRedirectURL
	}
	return DefaultBasePath + "/signin"
}

// registerProvider returns the credentials provider that handles sign-up,
// or nil when sign-up is off.
func (a *Authorization) registerProvider() *CredentialsProvider {
	if !a.endpoints.EnableRegister || a.endpoints.DisableCredentials {
		return nil
	}
	for _, p := range a.providers {
		if c, ok := p.(*CredentialsProvider); ok && c.Register != nil {
			return c
		}
	}
	return nil
}

// notFound answers requests for an endpoint that is switched off.
func notFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "Not found")
}
