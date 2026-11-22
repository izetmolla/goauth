package goauth

import (
	"cmp"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strings"
)

// EndpointOptions switches built-in API endpoints on or off. The zero value
// is the default: sign-in (OAuth, credentials) is on; sign-up is off.
// Password reset, email confirmation and one-time-code sign-in are switched
// on in Config.Verification. The HTML pages are switched on separately, in
// UIOptions.
type EndpointOptions struct {
	// DisableProviders removes GET {base}/providers.
	DisableProviders bool
	// DisablePages forces every built-in HTML page off, whatever UIOptions
	// says.
	//
	// Deprecated: pages are off unless UIOptions enables them.
	DisablePages bool
	// DisableCredentials stops credentials providers from signing users in
	// (POST {base}/provider/{id}) and hides the password form.
	DisableCredentials bool
	// EnableRegister turns on sign-up (POST {base}/provider/{id}/register)
	// for credentials providers that set Register. Off by default. The
	// sign-up page is switched on with UIOptions.EnableRegisterPage.
	EnableRegister bool
	// DisableCSRF removes GET {base}/csrf. The built-in pages still issue
	// their own CSRF token; this only removes the JSON endpoint used by SPAs.
	DisableCSRF bool
	// DisableSignOut removes POST {base}/signout.
	DisableSignOut bool
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

	// The built-in HTML pages are all off by default. Turn them on one by
	// one, or all at once with EnableAllUI. A page can only be on while its
	// feature is: sign-up needs Endpoints.EnableRegister and a provider with
	// Register; the forgot-password, one-time-code and verify-email pages
	// need the matching Config.Verification feature.

	// EnableAllUI turns on every page whose feature is on.
	EnableAllUI bool
	// EnableSignInPage serves the sign-in page.
	EnableSignInPage bool
	// EnableRegisterPage serves the sign-up page.
	EnableRegisterPage bool
	// EnableForgotPasswordPage serves the forgot-password page, where reset
	// links land.
	EnableForgotPasswordPage bool
	// EnableOTPPage serves the one-time-code page, where magic links land.
	EnableOTPPage bool
	// EnableVerifyPage serves the verify-email page, where confirmation
	// links land.
	EnableVerifyPage bool

	// Paths the pages are served at. Each must be a clean absolute path such
	// as "/sign-in". Defaults: {base}/signin, {base}/register,
	// {base}/forgot, {base}/otp and {base}/verify-email. Pages outside
	// DefaultBasePath are still served by Handler, so route those paths to
	// it too, for example mux.Handle("/sign-in", auth.Handler()).
	SignInEndpoint         string
	RegisterEndpoint       string
	ForgotPasswordEndpoint string
	OTPEndpoint            string
	VerifyEndpoint         string
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
// it is on, otherwise Config.SignInRedirectURL.
func (a *Authorization) signInPagePath() string {
	return cmp.Or(a.pagePath(pageSignIn), a.signInRedirectURL)
}

// pagePath returns the path a page is served at, or "" when it is off.
func (a *Authorization) pagePath(page string) string {
	if a == nil {
		return ""
	}
	return a.pages[page]
}

// pageSpec describes one page for resolvePages.
type pageSpec struct {
	name, field, enableField string
	enabled                  bool
	path, defaultPath        string
	available                bool   // its feature is on
	needs                    string // what turns the feature on
}

// reservedGETPaths are taken by API routes, so pages cannot use them.
func reservedGETPaths() []string {
	b := DefaultBasePath
	return []string{b + "/providers", b + "/csrf", b + "/password/reset", b + "/otp/verify"}
}

// resolvePages works out which pages are on and where, once, in New.
func (a *Authorization) resolvePages(u UIOptions) error {
	b := DefaultBasePath
	v := a.verify
	specs := []pageSpec{
		{pageSignIn, "SignInEndpoint", "EnableSignInPage", u.EnableSignInPage, u.SignInEndpoint, b + "/signin", true, ""},
		{pageRegister, "RegisterEndpoint", "EnableRegisterPage", u.EnableRegisterPage, u.RegisterEndpoint, b + "/register",
			a.registerProvider() != nil, "Endpoints.EnableRegister and a credentials provider with Register"},
		{pageForgot, "ForgotPasswordEndpoint", "EnableForgotPasswordPage", u.EnableForgotPasswordPage, u.ForgotPasswordEndpoint, b + "/forgot",
			v.reset.enabled, "Verification.PasswordReset.Enabled"},
		{pageOTP, "OTPEndpoint", "EnableOTPPage", u.EnableOTPPage, u.OTPEndpoint, b + "/otp",
			v.otp.enabled, "Verification.OTPSignIn.Enabled"},
		{pageVerify, "VerifyEndpoint", "EnableVerifyPage", u.EnableVerifyPage, u.VerifyEndpoint, b + "/verify-email",
			v.confirm.enabled, "Verification.EmailConfirmation.Enabled"},
	}
	a.pages = map[string]string{}
	used := map[string]string{}
	for _, s := range specs {
		if s.path != "" {
			if err := validPagePath(s.path); err != nil {
				return fmt.Errorf("UI.%s: %w", s.field, err)
			}
		}
		if s.enabled && !s.available {
			return fmt.Errorf("UI.%s needs %s", s.enableField, s.needs)
		}
		if a.endpoints.DisablePages || (!s.enabled && !u.EnableAllUI) || !s.available {
			continue
		}
		p := cmp.Or(s.path, s.defaultPath)
		if other, ok := used[p]; ok {
			return fmt.Errorf("UI.%s %q is already used by UI.%s", s.field, p, other)
		}
		if slices.Contains(reservedGETPaths(), p) || strings.HasPrefix(p, b+"/assets/") {
			return fmt.Errorf("UI.%s %q is reserved for an API route", s.field, p)
		}
		used[p] = s.field
		a.pages[s.name] = p
	}
	return nil
}

// validPagePath accepts clean absolute paths such as "/sign-in".
func validPagePath(p string) error {
	switch {
	case !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//"):
		return fmt.Errorf("%q must be an absolute path such as /sign-in", p)
	case len(p) > 200:
		return fmt.Errorf("%q is too long", p)
	case strings.ContainsAny(p, " \t?#{}%\\"):
		return fmt.Errorf("%q may not contain spaces, ?, #, %%, { } or backslashes", p)
	case path.Clean(p) != p:
		return fmt.Errorf("%q is not a clean path (no trailing slash, //, . or ..)", p)
	}
	return nil
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
