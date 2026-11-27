package goauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func uiAuth(t *testing.T, cfg Config) *Authorization {
	t.Helper()
	cfg.JWTSecret = "ui-secret-ui-secret-ui-secret-ui"
	cfg.DB = &gorm.DB{}
	cfg.UI.EnableAllUI = true // pages are off by default
	if cfg.Providers == nil {
		cfg.Providers = []Provider{
			&OAuthProvider{ProviderID: "google", DisplayName: "Google", Profile: testProfile},
			&OAuthProvider{ProviderID: "acme", DisplayName: "Acme SSO", Profile: testProfile},
			&CredentialsProvider{
				ProviderID: "credentials",
				Authorize: func(context.Context, map[string]string, *http.Request) (*OAuthUser, error) {
					return nil, &CredentialsError{Message: "Wrong password", Field: "password"}
				},
				Register: func(context.Context, map[string]string, *http.Request) (*OAuthUser, error) {
					return nil, nil
				},
				RegisterFields: []CredentialField{
					{Name: "name", Label: "Full name"},
					{Name: "email", Type: "email"},
					{Name: "password", Type: "password"},
				},
			},
		}
	}
	a, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func do(t *testing.T, h http.Handler, method, target string, body url.Values, header map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequestWithContext(t.Context(), method, target, nil)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSignInPageRendersProvidersAndForms(t *testing.T) {
	a := uiAuth(t, Config{
		UI:        UIOptions{AppName: "Flowtrove", AccentColor: "#7c3aed", TermsURL: "https://example.com/terms"},
		Endpoints: EndpointOptions{EnableRegister: true},
	})
	rec := do(t, a.Handler(), http.MethodGet, DefaultBasePath+"/signin?redirectUrl=/projects?id=1", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Continue with Google", "Continue with Acme SSO", `<svg viewBox="0 0 48 48"`, // known icon
		`class="ga-monogram" aria-hidden="true">A</span>`, // fallback monogram
		`data-page="signin"`, `id="ga-signin-email"`,
		`href="/api/authorization/register?redirectUrl=` + url.QueryEscape("/projects?id=1") + `"`,
		`autocomplete="current-password"`,
		`data-redirect="/projects?id=1"`, "Sign in to Flowtrove", "--ga-accent:#7c3aed",
		`href="https://example.com/terms"`, `name="csrfToken" value="`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") {
		t.Errorf("weak CSP: %s", csp)
	}
	if !strings.Contains(body, `nonce="`) {
		t.Error("accent style has no CSP nonce")
	}
	if c := rec.Result().Cookies(); len(c) == 0 || !strings.Contains(c[0].Name, "csrf-token") {
		t.Errorf("CSRF cookie not issued: %v", c)
	}
}

func TestSignInPageRejectsForeignRedirects(t *testing.T) {
	a := uiAuth(t, Config{})
	for _, target := range []string{"https://evil.test/x", "//evil.test/x", "/\\evil.test", "javascript:alert(1)"} {
		rec := do(t, a.Handler(), http.MethodGet, DefaultBasePath+"/signin?redirectUrl="+url.QueryEscape(target), nil, nil)
		if !strings.Contains(rec.Body.String(), `data-redirect="/"`) {
			t.Errorf("redirect %q was not replaced with /", target)
		}
	}
	// The web middleware sends absolute same-origin URLs; those are kept.
	rec := do(t, a.Handler(), http.MethodGet, DefaultBasePath+"/signin?redirectUrl="+url.QueryEscape("http://example.com/app?tab=2"), nil, nil)
	if !strings.Contains(rec.Body.String(), `data-redirect="/app?tab=2"`) {
		t.Error("same-origin absolute redirect was dropped")
	}
}

func TestUIPagesCarryRedirectUrlBetweenSignInAndRegister(t *testing.T) {
	a := uiAuth(t, Config{
		Endpoints: EndpointOptions{EnableRegister: true},
		Verification: VerificationOptions{
			PasswordReset: PasswordResetOptions{Enabled: true},
			OTPSignIn:     OTPSignInOptions{Enabled: true},
			FindUser:      func(context.Context, string) (*OAuthUser, error) { return nil, nil },
			Send:          func(context.Context, *VerificationMessage) error { return nil },
			SetPassword:   func(context.Context, string, string) error { return nil },
		},
	})
	h := a.Handler()
	target := "/projects?id=1"
	encoded := "redirectUrl=" + url.QueryEscape(target)

	signIn := do(t, h, http.MethodGet, DefaultBasePath+"/signin?redirectUrl="+url.QueryEscape(target), nil, nil)
	if signIn.Code != http.StatusOK {
		t.Fatalf("signin status %d", signIn.Code)
	}
	signInBody := signIn.Body.String()
	for _, want := range []string{
		`data-redirect="` + target + `"`,
		`name="redirectUrl" value="` + target + `"`,
		DefaultBasePath + "/register?" + encoded, // Sign up tab + Create an account
		DefaultBasePath + "/forgot?" + encoded,
		DefaultBasePath + "/otp?" + encoded,
	} {
		if !strings.Contains(signInBody, want) {
			t.Errorf("signin page missing %q", want)
		}
	}

	register := do(t, h, http.MethodGet, DefaultBasePath+"/register?redirectUrl="+url.QueryEscape(target), nil, nil)
	if register.Code != http.StatusOK {
		t.Fatalf("register status %d", register.Code)
	}
	registerBody := register.Body.String()
	for _, want := range []string{
		`data-redirect="` + target + `"`,
		`name="redirectUrl" value="` + target + `"`,
		DefaultBasePath + "/signin?" + encoded, // Sign in tab + Already have an account
	} {
		if !strings.Contains(registerBody, want) {
			t.Errorf("register page missing %q", want)
		}
	}
}

func TestWithRedirect(t *testing.T) {
	cases := []struct {
		path, redirect, want string
	}{
		{"/signin", "/app", "/signin?redirectUrl=%2Fapp"},
		{"/signin", "http://127.0.0.1:3001/x?y=1", "/signin?redirectUrl=http%3A%2F%2F127.0.0.1%3A3001%2Fx%3Fy%3D1"},
		{"/otp?step=request", "/home", "/otp?step=request&redirectUrl=%2Fhome"},
		{"/signin", "", "/signin"},
		{"", "/app", ""},
	}
	for _, c := range cases {
		if got := string(withRedirect(c.path, c.redirect)); got != c.want {
			t.Errorf("withRedirect(%q, %q) = %q, want %q", c.path, c.redirect, got, c.want)
		}
	}
}

func openCredentialsUITestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:cred_ui_"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  roles TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  type TEXT,
  ip_address TEXT,
  user_agent TEXT,
  method TEXT,
  logged_by TEXT,
  account TEXT,
  expires_at DATETIME,
  is_deleted NUMERIC DEFAULT 0,
  created_at DATETIME,
  updated_at DATETIME,
  deleted_at DATETIME
);`).Error; err != nil {
		t.Fatal(err)
	}
	return db
}

func TestCredentialsSignInAndRegisterHonorRedirectUrl(t *testing.T) {
	db := openCredentialsUITestDB(t)
	a, err := New(&Config{
		JWTSecret: "ui-redirect-secret-ui-redirect-secret",
		DB:        db,
		UI:        UIOptions{EnableAllUI: true, DefaultRedirect: "/dashboard"},
		Endpoints: EndpointOptions{EnableRegister: true},
		Providers: []Provider{
			&CredentialsProvider{
				ProviderID: "credentials",
				Authorize: func(context.Context, map[string]string, *http.Request) (*OAuthUser, error) {
					return &OAuthUser{ID: "user-1", Email: "a@b.c", Name: "Ada"}, nil
				},
				Register: func(context.Context, map[string]string, *http.Request) (*OAuthUser, error) {
					return &OAuthUser{ID: "user-2", Email: "new@b.c", Name: "New"}, nil
				},
				RegisterFields: []CredentialField{
					{Name: "email", Type: "email"},
					{Name: "password", Type: "password"},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Handler()
	jsonHdr := map[string]string{"Accept": "application/json"}
	csrfRec := do(t, h, http.MethodGet, DefaultBasePath+"/csrf", nil, nil)
	var tok struct{ CSRFToken string }
	_ = json.Unmarshal(csrfRec.Body.Bytes(), &tok)
	cookies := csrfRec.Result().Cookies()

	for _, tc := range []struct {
		name, path, redirect string
	}{
		{"sign-in", DefaultBasePath + "/provider/credentials", "/projects?tab=1"},
		{"register", DefaultBasePath + "/provider/credentials/register", "/welcome"},
		{"sign-in default", DefaultBasePath + "/provider/credentials", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{
				"email": {"a@b.c"}, "password": {"secret"}, "csrfToken": {tok.CSRFToken},
			}
			if tc.redirect != "" {
				form.Set("redirectUrl", tc.redirect)
			}
			rec := do(t, h, http.MethodPost, tc.path, form, jsonHdr, cookies...)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			var out map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out["type"] != "sign_in" {
				t.Fatalf("type=%v want sign_in body=%s", out["type"], rec.Body.String())
			}
			want := tc.redirect
			if want == "" {
				want = "/dashboard"
			}
			if out["redirect_url"] != want {
				t.Fatalf("redirect_url=%v want %q", out["redirect_url"], want)
			}
		})
	}
}

func TestEndpointsCanBeDisabled(t *testing.T) {
	a := uiAuth(t, Config{Endpoints: EndpointOptions{
		DisableProviders: true, DisablePages: true, DisableCSRF: true,
	}})
	h := a.Handler()
	for _, p := range []string{"/providers", "/signin", "/csrf", "/assets/goauth.css", "/register", "/forgot", "/otp", "/verify-email"} {
		if rec := do(t, h, http.MethodGet, DefaultBasePath+p, nil, nil); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodPost, DefaultBasePath+"/provider/credentials/register", url.Values{}, nil); rec.Code == http.StatusOK {
		t.Error("register still enabled")
	}
	// Exported handlers mounted directly honor the switches too.
	if rec := do(t, http.HandlerFunc(a.SignInPage), http.MethodGet, "/signin", nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("SignInPage = %d, want 404", rec.Code)
	}
}

func TestDisableCredentialsHidesFormAndEndpoint(t *testing.T) {
	a := uiAuth(t, Config{Endpoints: EndpointOptions{DisableCredentials: true}})
	h := a.Handler()
	body := do(t, h, http.MethodGet, DefaultBasePath+"/signin", nil, nil).Body.String()
	if strings.Contains(body, "ga-form-signin") || !strings.Contains(body, "Continue with Google") {
		t.Error("credentials form still shown, or OAuth buttons missing")
	}
	if rec := do(t, h, http.MethodPost, DefaultBasePath+"/provider/credentials", url.Values{}, nil); rec.Code != http.StatusNotFound {
		t.Errorf("credentials endpoint = %d, want 404", rec.Code)
	}
}

func TestCredentialsRequireCSRFAndReturnUserFacingErrors(t *testing.T) {
	a := uiAuth(t, Config{})
	h := a.Handler()
	jsonHdr := map[string]string{"Accept": "application/json"}
	form := url.Values{"email": {"a@b.c"}, "password": {"x"}}

	// No CSRF token: rejected, and the app's Authorize is never reached.
	rec := do(t, h, http.MethodPost, DefaultBasePath+"/provider/credentials", form, jsonHdr)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("without CSRF = %d, want 403", rec.Code)
	}
	// ?flow=token no longer skips CSRF; only the X-Auth-Flow header does.
	if rec := do(t, h, http.MethodPost, DefaultBasePath+"/provider/credentials?flow=token", form, jsonHdr); rec.Code != http.StatusForbidden {
		t.Fatalf("?flow=token bypassed CSRF: %d", rec.Code)
	}

	// With the token from /csrf: the CredentialsError message comes back.
	csrfRec := do(t, h, http.MethodGet, DefaultBasePath+"/csrf", nil, nil)
	var tok struct{ CSRFToken string }
	_ = json.Unmarshal(csrfRec.Body.Bytes(), &tok)
	form.Set("csrfToken", tok.CSRFToken)
	rec = do(t, h, http.MethodPost, DefaultBasePath+"/provider/credentials", form, jsonHdr, csrfRec.Result().Cookies()...)
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusUnauthorized || out["message"] != "Wrong password" || out["field"] != "password" {
		t.Fatalf("got %d %v", rec.Code, out)
	}

	// No-JS form post: redirected back to the page with only an error code.
	rec = do(t, h, http.MethodPost, DefaultBasePath+"/provider/credentials", form, nil, csrfRec.Result().Cookies()...)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != DefaultBasePath+"/signin?error=CREDENTIALS_SIGNIN&field=password" {
		t.Fatalf("no-JS failure = %d %s", rec.Code, rec.Header().Get("Location"))
	}

	// GET is not allowed.
	if rec := do(t, h, http.MethodGet, DefaultBasePath+"/provider/credentials", nil, jsonHdr); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", rec.Code)
	}
}

func TestCSRFTokenIsReusedWhileValid(t *testing.T) {
	a := uiAuth(t, Config{})
	h := a.Handler()
	first := do(t, h, http.MethodGet, DefaultBasePath+"/csrf", nil, nil)
	second := do(t, h, http.MethodGet, DefaultBasePath+"/csrf", nil, nil, first.Result().Cookies()...)
	if first.Body.String() != second.Body.String() {
		t.Error("a valid CSRF cookie was replaced; other open tabs would break")
	}
	if len(second.Result().Cookies()) != 0 {
		t.Error("cookie re-issued although it was valid")
	}
}

func TestAssetsAreVersionedAndCached(t *testing.T) {
	a := uiAuth(t, Config{})
	h := a.Handler()
	rec := do(t, h, http.MethodGet, DefaultBasePath+"/assets/goauth.js?v="+uiAssetVersion, nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") ||
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/javascript") {
		t.Fatalf("asset: %d %v", rec.Code, rec.Header())
	}
	etag := rec.Header().Get("ETag")
	if rec := do(t, h, http.MethodGet, DefaultBasePath+"/assets/goauth.js", nil, map[string]string{"If-None-Match": etag}); rec.Code != http.StatusNotModified {
		t.Errorf("conditional GET = %d, want 304", rec.Code)
	}
	for _, p := range []string{"signin.html", "..%2Fui.go", "missing.css"} {
		if rec := do(t, h, http.MethodGet, DefaultBasePath+"/assets/"+p, nil, nil); rec.Code != http.StatusNotFound {
			t.Errorf("asset %s = %d, want 404", p, rec.Code)
		}
	}
}

func TestUIOptionsValidation(t *testing.T) {
	for _, ui := range []UIOptions{
		{AccentColor: "red;}body{display:none"},
		{AccentColor: "url(https://evil.test)"},
		{DefaultRedirect: "https://evil.test"},
	} {
		if err := ui.validate(); err == nil {
			t.Errorf("accepted %+v", ui)
		}
	}
	for _, c := range []string{"#7c3aed", "oklch(0.55 0.2 270)", "rgb(10, 20, 30)", "rebeccapurple"} {
		if err := (UIOptions{AccentColor: c}).validate(); err != nil {
			t.Errorf("rejected %q: %v", c, err)
		}
	}
}

func TestSanitizeRedirectPath(t *testing.T) {
	cases := map[string]string{
		"/":               "/",
		"/a/b?x=1#frag":   "/a/b?x=1#frag",
		"//evil.test":     "",
		"/\\evil.test":    "",
		"https://evil.io": "",
		"relative":        "",
		"":                "",
	}
	for in, want := range cases {
		if got := sanitizeRedirectPath(in); got != want {
			t.Errorf("sanitizeRedirectPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// testProfile is a minimal Profile function for providers that tests only list.
func testProfile(p Profile, _ TokenSet) (*OAuthUser, error) {
	id, _ := p["sub"].(string)
	return &OAuthUser{ID: id}, nil
}
