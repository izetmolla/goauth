package goauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"gorm.io/gorm"
)

// allFeatures is a config with every verification feature and sign-up on,
// so only UIOptions decides which pages exist.
func allFeatures(ui UIOptions) *Config {
	return &Config{
		JWTSecret: "pages-secret-pages-secret-pages", DB: &gorm.DB{},
		Endpoints: EndpointOptions{EnableRegister: true},
		UI:        ui,
		Providers: []Provider{
			&OAuthProvider{ProviderID: "google", DisplayName: "Google", Profile: testProfile},
			&CredentialsProvider{
				ProviderID: "credentials",
				Authorize: func(context.Context, map[string]string, *http.Request) (*OAuthUser, error) {
					return nil, &CredentialsError{Message: "nope"}
				},
				Register: func(context.Context, map[string]string, *http.Request) (*OAuthUser, error) { return nil, nil },
			},
		},
		Verification: VerificationOptions{
			PasswordReset:     PasswordResetOptions{Enabled: true},
			EmailConfirmation: EmailConfirmationOptions{Enabled: true},
			OTPSignIn:         OTPSignInOptions{Enabled: true},
			FindUser:          func(context.Context, string) (*OAuthUser, error) { return nil, nil },
			Send:              func(context.Context, *VerificationMessage) error { return nil },
			SetPassword:       func(context.Context, string, string) error { return nil },
			MarkVerified:      func(context.Context, string) error { return nil },
		},
	}
}

func mustNew(t *testing.T, c *Config) *Authorization {
	t.Helper()
	a, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var defaultPages = []string{"/signin", "/register", "/forgot", "/otp", "/verify-email"}

func TestAllPagesOffByDefault(t *testing.T) {
	h := mustNew(t, allFeatures(UIOptions{})).Handler()
	// No page is served: 404, or 405 where only a POST API lives at that path.
	for _, p := range append(defaultPages, "/assets/goauth.css", "/password/reset", "/otp/verify") {
		if rec := do(t, h, http.MethodGet, DefaultBasePath+p, nil, nil); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 404/405", p, rec.Code)
		}
	}
	// The APIs are still there: these fail CSRF (403), not 404.
	for _, p := range []string{"/otp/send", "/password/forgot", "/verify-email/send", "/provider/credentials/register"} {
		if rec := do(t, h, http.MethodPost, DefaultBasePath+p, url.Values{"email": {"a@b.co"}}, nil); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s = %d, want 403 (route present)", p, rec.Code)
		}
	}
}

func TestPagesOneByOne(t *testing.T) {
	a := mustNew(t, allFeatures(UIOptions{EnableOTPPage: true}))
	h := a.Handler()
	if rec := do(t, h, http.MethodGet, DefaultBasePath+"/otp", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("OTP page = %d", rec.Code)
	}
	for _, p := range []string{"/signin", "/register", "/forgot", "/verify-email"} {
		if rec := do(t, h, http.MethodGet, DefaultBasePath+p, nil, nil); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 404/405", p, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodGet, DefaultBasePath+"/assets/goauth.js", nil, nil); rec.Code != http.StatusOK {
		t.Error("assets missing while a page is on")
	}
	// The sign-in page is off, so "Back to sign in" uses SignInRedirectURL.
	body := do(t, h, http.MethodGet, DefaultBasePath+"/otp", nil, nil).Body.String()
	if !strings.Contains(body, `href="`+DefaultSignInRedirectURL+`"`) {
		t.Error("back link does not fall back to SignInRedirectURL")
	}
	// Forgot/verify pages are off: password reset and confirmation emails
	// carry codes only; OTP keeps its magic link.
	if a.verify.reset.code.Delivery != DeliverCode || a.verify.confirm.code.Delivery != DeliverCode || a.verify.otp.code.Delivery != DeliverCodeAndLink {
		t.Errorf("deliveries: reset=%v confirm=%v otp=%v", a.verify.reset.code.Delivery, a.verify.confirm.code.Delivery, a.verify.otp.code.Delivery)
	}
}

func TestEnableAllUIOnlyTurnsOnAvailablePages(t *testing.T) {
	c := allFeatures(UIOptions{EnableAllUI: true})
	c.Verification.OTPSignIn.Enabled = false
	c.Endpoints.EnableRegister = false
	h := mustNew(t, c).Handler()
	want := map[string]int{"/signin": 200, "/forgot": 200, "/verify-email": 200, "/otp": 404, "/register": 404}
	for p, code := range want {
		if rec := do(t, h, http.MethodGet, DefaultBasePath+p, nil, nil); rec.Code != code {
			t.Errorf("GET %s = %d, want %d", p, rec.Code, code)
		}
	}
}

func TestCustomPagePaths(t *testing.T) {
	a := mustNew(t, allFeatures(UIOptions{
		EnableAllUI:            true,
		SignInEndpoint:         "/sign-in",
		RegisterEndpoint:       "/sign-up",
		ForgotPasswordEndpoint: "/account/forgot",
		OTPEndpoint:            "/login/code",
		VerifyEndpoint:         "/account/verify",
	}))
	h := a.Handler()
	for _, p := range []string{"/sign-in", "/sign-up", "/account/forgot", "/login/code", "/account/verify"} {
		if rec := do(t, h, http.MethodGet, p, nil, nil); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", p, rec.Code)
		}
	}
	for _, p := range []string{"/signin", "/register", "/forgot", "/otp"} {
		if rec := do(t, h, http.MethodGet, DefaultBasePath+p, nil, nil); rec.Code != http.StatusNotFound {
			t.Errorf("old path GET %s = %d, want 404", p, rec.Code)
		}
	}
	// Links between pages use the new paths.
	body := do(t, h, http.MethodGet, "/sign-in", nil, nil).Body.String()
	for _, link := range []string{`href="/sign-up"`, `href="/account/forgot"`, `href="/login/code?`} {
		if !strings.Contains(body, link) {
			t.Errorf("sign-in page missing %s", link)
		}
	}
	// Email links land on the custom pages.
	if got := a.pagePath(pageForKind(KindOTPSignIn)); got != "/login/code" {
		t.Errorf("OTP link page = %q", got)
	}
	// A failed no-JS sign-in goes back to the custom sign-in path.
	csrfRec := do(t, h, http.MethodGet, DefaultBasePath+"/csrf", nil, nil)
	tok, _, _ := strings.Cut(strings.Split(csrfRec.Body.String(), `"csrfToken":"`)[1], `"`)
	rec := do(t, h, http.MethodPost, DefaultBasePath+"/provider/credentials",
		url.Values{"csrfToken": {tok}, "email": {"a@b.co"}, "password": {"x"}}, nil, csrfRec.Result().Cookies()...)
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/sign-in?") {
		t.Errorf("no-JS failure redirect = %q", loc)
	}
	// Old email links (v1.2.0) still open the page.
	if rec := do(t, h, http.MethodGet, DefaultBasePath+"/otp/verify?email=a%40b.co&token=t", nil, nil); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `data-step="link"`) {
		t.Errorf("legacy magic link = %d", rec.Code)
	}
	if a.signInPagePath() != "/sign-in" {
		t.Errorf("signInPagePath = %q", a.signInPagePath())
	}
}

func TestPageConfigErrors(t *testing.T) {
	cases := map[string]func(*Config){
		"relative path":    func(c *Config) { c.UI.EnableAllUI = true; c.UI.SignInEndpoint = "sign-in" },
		"trailing slash":   func(c *Config) { c.UI.EnableAllUI = true; c.UI.SignInEndpoint = "/sign-in/" },
		"wildcard":         func(c *Config) { c.UI.EnableAllUI = true; c.UI.OTPEndpoint = "/otp/{x}" },
		"query":            func(c *Config) { c.UI.EnableAllUI = true; c.UI.OTPEndpoint = "/otp?x=1" },
		"duplicate":        func(c *Config) { c.UI.EnableAllUI = true; c.UI.SignInEndpoint = "/auth"; c.UI.OTPEndpoint = "/auth" },
		"reserved":         func(c *Config) { c.UI.EnableAllUI = true; c.UI.SignInEndpoint = DefaultBasePath + "/csrf" },
		"assets":           func(c *Config) { c.UI.EnableAllUI = true; c.UI.SignInEndpoint = DefaultBasePath + "/assets/x" },
		"page w/o feature": func(c *Config) { c.Verification.OTPSignIn.Enabled = false; c.UI.EnableOTPPage = true },
		"register w/o api": func(c *Config) { c.Endpoints.EnableRegister = false; c.UI.EnableRegisterPage = true },
	}
	for name, mutate := range cases {
		c := allFeatures(UIOptions{})
		mutate(c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
