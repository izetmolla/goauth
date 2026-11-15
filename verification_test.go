package goauth

import (
	"context"
	"math"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"gorm.io/gorm"
)

func TestRandomCodeIsUniformAndUsesCharset(t *testing.T) {
	const n, length = 20000, 6
	counts := map[byte]int{}
	for range n {
		c := randomCode(length, CharsetNumeric)
		if len(c) != length {
			t.Fatalf("length %d", len(c))
		}
		for i := range len(c) {
			counts[c[i]]++
		}
	}
	if len(counts) != 10 {
		t.Fatalf("used %d distinct digits, want 10", len(counts))
	}
	// Each digit should appear ~12000 times; allow 5 sigma.
	want := float64(n*length) / 10
	sigma := math.Sqrt(want * 0.9)
	for d, c := range counts {
		if math.Abs(float64(c)-want) > 5*sigma {
			t.Errorf("digit %c appeared %d times, want about %.0f", d, c, want)
		}
	}
	for range 200 {
		c := randomCode(8, CharsetUnambiguous)
		if strings.ContainsAny(c, "01OIL") {
			t.Fatalf("ambiguous character in %q", c)
		}
	}
}

func TestNormalizeCode(t *testing.T) {
	if got := normalizeCode(" ab-c 12 ", CharsetAlphanumeric); got != "ABC12" {
		t.Errorf("got %q", got)
	}
	if got := normalizeCode("aBc", "abcABC"); got != "aBc" {
		t.Errorf("case folded although charset is mixed case: %q", got)
	}
}

func TestNormalizeEmail(t *testing.T) {
	cases := map[string]string{
		" Jane@Example.COM ":               "jane@example.com",
		"jane@example":                     "",
		"Jane <jane@example.com>":          "",
		"a@b.co, c@d.co":                   "",
		"not an email":                     "",
		strings.Repeat("a", 250) + "@x.io": "",
	}
	for in, want := range cases {
		if got := normalizeEmail(in); got != want {
			t.Errorf("normalizeEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVerificationOptionsValidation(t *testing.T) {
	find := func(context.Context, string) (*OAuthUser, error) { return nil, nil }
	send := func(context.Context, *VerificationMessage) error { return nil }
	bad := map[string]VerificationOptions{
		"no hooks":           {OTPSignIn: OTPSignInOptions{Enabled: true}},
		"reset without set":  {PasswordReset: PasswordResetOptions{Enabled: true}, FindUser: find, Send: send},
		"confirm without mv": {EmailConfirmation: EmailConfirmationOptions{Enabled: true}, FindUser: find, Send: send},
		"short code":         {OTPSignIn: OTPSignInOptions{Enabled: true, Code: CodeOptions{Length: 3}}, FindUser: find, Send: send},
		"dup charset":        {OTPSignIn: OTPSignInOptions{Code: CodeOptions{Charset: "AAB"}}},
		"huge ttl":           {OTPSignIn: OTPSignInOptions{Code: CodeOptions{TTL: 30 * 24 * time.Hour}}},
		"bad template":       {EmailTemplates: fstest.MapFS{"otp_signin.html": {Data: []byte(`{{define "subject"}}x`)}}},
	}
	for name, o := range bad {
		if _, err := newVerification(o, "secret"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	v, err := newVerification(VerificationOptions{OTPSignIn: OTPSignInOptions{Enabled: true}, FindUser: find, Send: send}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if v.otp.code.Length != 6 || v.otp.code.TTL != 10*time.Minute || v.otp.code.Delivery != DeliverCodeAndLink ||
		v.reset.code.Delivery != DeliverLink || v.confirm.code.TTL != 24*time.Hour {
		t.Errorf("defaults not applied: %+v", v)
	}
	if v.reset.enabled || v.confirm.enabled {
		t.Error("features enabled by default")
	}
}

func TestLinksNeedPages(t *testing.T) {
	cfg := func(d Delivery) *Config {
		return &Config{
			JWTSecret: "s", DB: &gorm.DB{},
			Verification: VerificationOptions{
				OTPSignIn: OTPSignInOptions{Enabled: true, Code: CodeOptions{Delivery: d}},
				FindUser:  func(context.Context, string) (*OAuthUser, error) { return nil, nil },
				Send:      func(context.Context, *VerificationMessage) error { return nil },
			},
		}
	}
	// Links asked for explicitly, but the OTP page is off: refused.
	if _, err := New(cfg(DeliverLink)); err == nil || !strings.Contains(err.Error(), "DeliverCode") {
		t.Fatalf("explicit links without a page: %v", err)
	}
	// Default delivery with the page off: emails fall back to codes only.
	a, err := New(cfg(DeliverDefault))
	if err != nil {
		t.Fatal(err)
	}
	if d := a.verify.otp.code.Delivery; d != DeliverCode {
		t.Fatalf("delivery = %v, want DeliverCode", d)
	}
	// With the page on, the default (code + link) stays.
	c := cfg(DeliverDefault)
	c.UI.EnableOTPPage = true
	if a, err = New(c); err != nil || a.verify.otp.code.Delivery != DeliverCodeAndLink {
		t.Fatalf("with page: %v %v", err, a.verify.otp.code.Delivery)
	}
}

func TestVerificationEndpointsOffByDefault(t *testing.T) {
	a := uiAuth(t, Config{})
	h := a.Handler()
	for _, p := range []string{"/register", "/forgot", "/otp", "/verify-email", "/password/reset", "/otp/verify"} {
		if rec := do(t, h, http.MethodGet, DefaultBasePath+p, nil, nil); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, rec.Code)
		}
	}
	for _, p := range []string{"/password/forgot", "/password/reset", "/otp/send", "/otp/verify", "/verify-email", "/verify-email/send", "/provider/credentials/register"} {
		if rec := do(t, h, http.MethodPost, DefaultBasePath+p, nil, nil); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 404/405", p, rec.Code)
		}
	}
	body := do(t, h, http.MethodGet, DefaultBasePath+"/signin", nil, nil).Body.String()
	for _, link := range []string{"/forgot", "/otp", "/register"} {
		if strings.Contains(body, DefaultBasePath+link) {
			t.Errorf("sign-in page links to disabled %s", link)
		}
	}
}

func TestEmailTemplatesRenderAndCanBeOverridden(t *testing.T) {
	a := uiAuth(t, Config{UI: UIOptions{AppName: "Flowtrove"}})
	msg := &VerificationMessage{Kind: KindOTPSignIn, To: "jane@example.com", Code: "123456",
		Link: "https://app.test/api/authorization/otp/verify?email=jane%40example.com&token=abc", ExpiresAt: time.Now().Add(10 * time.Minute)}
	if err := a.renderEmail(msg); err != nil {
		t.Fatal(err)
	}
	if msg.Subject != "123456 is your Flowtrove sign-in code" {
		t.Errorf("subject %q", msg.Subject)
	}
	// Plain text keeps the link intact (no HTML escaping of &).
	if !strings.Contains(msg.Text, "?email=jane%40example.com&token=abc") || !strings.Contains(msg.Text, "10 minutes") {
		t.Errorf("text:\n%s", msg.Text)
	}
	if !strings.Contains(msg.HTML, `href="https://app.test/api/authorization/otp/verify?email=jane%40example.com&amp;token=abc"`) ||
		!strings.Contains(msg.HTML, ">123456</td>") {
		t.Errorf("html missing link or code")
	}

	override := fstest.MapFS{"otp_signin.html": {Data: []byte(`{{define "subject"}}Code {{.Code}}{{end}}{{define "preheader"}}{{end}}{{define "text"}}Use {{.Code}}{{end}}{{define "html"}}<b>{{.Code}}</b>{{end}}`)}}
	v, err := newVerification(VerificationOptions{EmailTemplates: override}, "s")
	if err != nil {
		t.Fatal(err)
	}
	a.verify = v
	if err := a.renderEmail(msg); err != nil {
		t.Fatal(err)
	}
	if msg.Subject != "Code 123456" || msg.Text != "Use 123456\n" || !strings.Contains(msg.HTML, "<b>123456</b>") {
		t.Errorf("override not used: %q %q", msg.Subject, msg.Text)
	}
}

func TestHumanDuration(t *testing.T) {
	cases := map[time.Duration]string{
		10 * time.Minute: "10 minutes", time.Minute: "1 minute", time.Hour: "1 hour",
		24 * time.Hour: "24 hours", 72 * time.Hour: "3 days", 90 * time.Minute: "90 minutes",
	}
	for d, want := range cases {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestPickStep(t *testing.T) {
	cases := []struct {
		page, want         string
		hasToken, hasEmail bool
		out                string
	}{
		{"forgot", "", false, false, "request"},
		{"forgot", "code", false, true, "code"},
		{"forgot", "code", false, false, "request"}, // a code step needs an email
		{"forgot", "reset", false, true, "request"}, // reset needs a token
		{"forgot", "", true, true, "reset"},
		{"otp", "", true, true, "link"},
		{"otp", "bogus", false, true, "request"},
		{"verify", "done", false, false, "done"},
	}
	for _, c := range cases {
		if got := pickStep(c.page, c.want, c.hasToken, c.hasEmail); got != c.out {
			t.Errorf("pickStep(%s, %q, %v, %v) = %q, want %q", c.page, c.want, c.hasToken, c.hasEmail, got, c.out)
		}
	}
}
