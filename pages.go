package goauth

import (
	"bytes"
	"cmp"
	"html/template"
	"net/http"
	"net/url"
	"slices"
)

// pageTemplates holds one template set per page: the shared layout plus the
// page's own "content" (and title/heading) blocks.
var pageTemplates = func() map[string]*template.Template {
	out := map[string]*template.Template{}
	for _, name := range []string{formSignIn, formReg, formForgot, formOTP, formVerify} {
		out[name] = template.Must(template.New(name).Funcs(pageFuncs).ParseFS(uiFiles, "ui/layout.html", "ui/"+name+".html"))
	}
	return out
}()

// pageFuncs are the helpers the page templates use.
var pageFuncs = template.FuncMap{
	// fieldError bundles an error message with the id an input's
	// aria-describedby points at.
	"fieldError": func(id, message string) fieldErrorView { return fieldErrorView{ID: id, Message: message} },
}

type fieldErrorView struct{ ID, Message string }

// pageSteps lists the steps each page can show; the first is the default.
// Steps marked by a link token ("reset", "link") are only shown when the
// URL carries one.
var pageSteps = map[string][]string{
	formSignIn: {"form"},
	formReg:    {"form", stepSent},
	formForgot: {stepRequest, stepCode, stepReset, stepSent, stepDone},
	formOTP:    {stepRequest, stepCode, stepLink, stepSent},
	formVerify: {stepRequest, stepCode, stepLink, stepSent, stepDone},
}

type pageData struct {
	Page        string
	AppName     string
	LogoURL     string
	AccentColor template.CSS
	TermsURL    string
	PrivacyURL  string
	Nonce       string

	CSSURL, JSURL, SessionJSURL string

	Step string
	// Vid is the verification id the multi-step pages continue with. The
	// email address never travels in the URL.
	Vid       string
	Token     string
	Redirect  string
	CSRFToken string
	Error     string
	// ErrorField is the input the error is about; ErrorPlaced reports that
	// the page shows the message under that input instead of in the alert.
	ErrorField  string
	ErrorPlaced bool

	Links pageLinks
	// Actions are the POST endpoints the page's forms submit to.
	Actions      map[string]string
	ResendAction string

	OAuth       []oauthButton
	Credentials *credentialsView
	Code        codeView
	MinPassword int
}

// pageLinks point to the other pages; "" when that page is off.
type pageLinks struct {
	SignIn, Register, Forgot, OTP, Verify string
}

type codeView struct {
	Length      int
	Numeric     bool
	HasCode     bool
	HasLink     bool
	ResendAfter int
}

type oauthButton struct {
	ID   string
	Name string
	URL  string
	Icon template.HTML
}

type credentialsView struct {
	ID     string
	Action string
	Fields []fieldView
}

type fieldView struct {
	ID, Name, Label, Type, Placeholder, Autocomplete string
	IsPassword                                       bool
	Error                                            string // shown under the input
}

// errorMessages maps the error codes a no-JS form post is redirected with.
// Only these fixed strings are ever shown, so the query string cannot be
// used to inject text into the page.
var errorMessages = map[string]string{
	codeCredentialsSignin: "Those credentials didn't work. Check them and try again.",
	codeRegisterFailed:    "We couldn't create your account. Check the details and try again.",
	codeCSRF:              "Your session expired. Please try again.",
	codeBadRequest:        "Something was wrong with the form. Please try again.",
	codeServerError:       "Something went wrong on our side. Please try again.",
	codeEmailNotVerified:  "Please confirm your email first. We've sent you a new confirmation email.",
	codeInvalidCode:       "That code is invalid or has expired. Request a new one and try again.",
	codeCodeExpired:       "That code or link has expired. Request a new one and try again.",
	codeCodeUsed:          "That code or link has already been used. Request a new one if you still need to reset your password.",
	codeInvalidEmail:      "Enter a valid email address.",
	codeWeakPassword:      "That password is too short.",
	codeLoginLocked:       "Too many incorrect sign-in attempts. Try again later.",
}

// SignInPage implements GET {base}/signin: every enabled provider as a
// button, plus the password form of the first credentials provider.
// Query parameters: redirectUrl (or callbackUrl), a same-origin target.
func (a *Authorization) SignInPage(w http.ResponseWriter, r *http.Request) {
	a.renderPage(w, r, formSignIn, func(d *pageData) {
		d.OAuth = a.oauthButtons()
		if p := a.credentialsProvider(); p != nil {
			d.Credentials = &credentialsView{
				ID:     p.ID(),
				Action: DefaultBasePath + "/provider/" + url.PathEscape(p.ID()),
				Fields: fieldViews(p.signInFields(), formSignIn),
			}
		}
	})
}

// RegisterPage implements GET {base}/register (Endpoints.EnableRegister).
func (a *Authorization) RegisterPage(w http.ResponseWriter, r *http.Request) {
	a.renderPage(w, r, formReg, func(d *pageData) {
		p := a.registerProvider()
		d.OAuth = a.oauthButtons()
		d.Credentials = &credentialsView{
			ID:     p.ID(),
			Action: DefaultBasePath + "/provider/" + url.PathEscape(p.ID()) + "/register",
			Fields: fieldViews(p.registerFields(), formReg),
		}
		if a.verify != nil && a.verify.confirm.enabled {
			d.Code = a.codeView(&a.verify.confirm)
			d.ResendAction = pageActions["verifySend"]
		}
	})
}

// ForgotPasswordPage implements GET {base}/forgot and the reset link
// landing page GET {base}/password/reset?email=…&token=….
func (a *Authorization) ForgotPasswordPage(w http.ResponseWriter, r *http.Request) {
	a.renderPage(w, r, formForgot, func(d *pageData) {
		d.Code = a.codeView(&a.verify.reset)
		d.ResendAction = pageActions[formForgot]
		d.MinPassword = a.verify.opts.PasswordReset.MinPasswordLength
	})
}

// OTPPage implements GET {base}/otp and the magic link landing page
// GET {base}/otp/verify?email=…&token=….
func (a *Authorization) OTPPage(w http.ResponseWriter, r *http.Request) {
	a.renderPage(w, r, formOTP, func(d *pageData) {
		d.Code = a.codeView(&a.verify.otp)
		d.ResendAction = pageActions["otpSend"]
	})
}

// VerifyEmailPage implements GET {base}/verify-email, including the
// confirmation link landing page (?email=…&token=…).
func (a *Authorization) VerifyEmailPage(w http.ResponseWriter, r *http.Request) {
	a.renderPage(w, r, formVerify, func(d *pageData) {
		d.Code = a.codeView(&a.verify.confirm)
		d.ResendAction = pageActions["verifySend"]
	})
}

// renderPage builds the data every page shares, lets the page add its own,
// and writes it with strict security headers. Link landing pages never act
// on the token by themselves (email scanners prefetch links); the user
// confirms with a button that POSTs it.
func (a *Authorization) renderPage(w http.ResponseWriter, r *http.Request, page string, fill func(*pageData)) {
	if a == nil {
		writeError(w, http.StatusInternalServerError, ErrNotInitialized.Error())
		return
	}
	if a.pagePath(page) == "" {
		notFound(w)
		return
	}
	origin, secure, err := a.origin(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get origin")
		return
	}
	q := r.URL.Query()
	d := pageData{
		Page:         page,
		AppName:      a.ui.AppName,
		LogoURL:      a.ui.LogoURL,
		AccentColor:  template.CSS(a.ui.AccentColor), // validated in New
		TermsURL:     a.ui.TermsURL,
		PrivacyURL:   a.ui.PrivacyURL,
		Nonce:        randomString(16),
		CSSURL:       assetURL("goauth.css"),
		JSURL:        assetURL("goauth.js"),
		SessionJSURL: assetURL("session.js"),
		Token:        q.Get(fieldToken),
		Redirect: cmp.Or(
			a.safeRedirect(cmp.Or(q.Get("redirectUrl"), q.Get("callbackUrl"))),
			sameOriginRedirect(origin, cmp.Or(q.Get("redirectUrl"), q.Get("callbackUrl"))),
			a.defaultRedirect(),
		),
		CSRFToken:    a.ensureCSRFToken(w, r, secure),
		Error:        errorMessages[q.Get("error")],
		Links:        a.pageLinks(),
		Actions:      pageActions,
	}
	if len(d.Token) > 128 {
		d.Token = ""
	}
	if vid := q.Get(fieldVID); validVID(vid) {
		d.Vid = vid
	}
	d.Step = pickStep(page, q.Get("step"), d.Token != "", d.Vid != "")
	if d.Error != "" && fieldName.MatchString(q.Get("field")) {
		d.ErrorField = q.Get("field")
	}
	fill(&d)
	placeFieldError(&d)

	var buf bytes.Buffer
	if err := pageTemplates[page].ExecuteTemplate(&buf, "layout", d); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to render page")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	// Link pages carry a token in the URL: never leak it in a Referer.
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'nonce-"+d.Nonce+
		"'; img-src 'self' data: https:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	_, _ = w.Write(buf.Bytes())
}

// placeFieldError puts a no-JS error under its input when the page shows
// that input; otherwise the error stays in the alert at the top.
func placeFieldError(d *pageData) {
	if d.ErrorField == "" {
		return
	}
	if d.Credentials != nil {
		for i := range d.Credentials.Fields {
			if d.Credentials.Fields[i].Name == d.ErrorField {
				d.Credentials.Fields[i].Error = d.Error
				d.ErrorPlaced = true
			}
		}
		return
	}
	d.ErrorPlaced = (d.ErrorField == inputEmail && d.Step == stepRequest) || (d.ErrorField == stepCode && d.Step == stepCode)
}

// pickStep chooses the step to show from ?step=, falling back to the page's
// first step. Token steps need a token; code steps need a verification id.
func pickStep(page, want string, hasToken, hasVID bool) string {
	steps := pageSteps[page]
	if hasToken {
		for _, s := range []string{stepLink, stepReset} {
			if slices.Contains(steps, s) {
				return s
			}
		}
	}
	switch {
	case want == stepLink || want == stepReset:
		return steps[0]
	case (want == stepCode || want == stepSent) && !hasVID:
		return steps[0]
	case slices.Contains(steps, want):
		return want
	}
	return steps[0]
}

var pageActions = map[string]string{
	formForgot:    DefaultBasePath + "/password/forgot",
	"resetVerify": DefaultBasePath + "/password/verify-code",
	"reset":       DefaultBasePath + "/password/reset",
	"otpSend":     DefaultBasePath + "/otp/send",
	"otpVerify":   DefaultBasePath + "/otp/verify",
	"verifySend":  DefaultBasePath + "/verify-email/send",
	formVerify:    DefaultBasePath + "/verify-email",
}

func (a *Authorization) pageLinks() pageLinks {
	l := pageLinks{
		// Your own sign-in URL when the built-in page is off.
		SignIn:   a.signInPagePath(),
		Register: a.pagePath(pageRegister),
		OTP:      a.pagePath(pageOTP),
		Verify:   a.pagePath(pageVerify),
	}
	// "Forgot password?" sits under the password field.
	if a.credentialsProvider() != nil {
		l.Forgot = a.pagePath(pageForgot)
	}
	return l
}

func (a *Authorization) codeView(f *verifyFeature) codeView {
	return codeView{
		Length:      f.code.Length,
		Numeric:     f.code.Charset == CharsetNumeric,
		HasCode:     f.code.Delivery.hasCode(),
		HasLink:     f.code.Delivery.hasLink(),
		ResendAfter: int(max(f.code.ResendAfter, 0).Seconds()),
	}
}

func (a *Authorization) oauthButtons() []oauthButton {
	var out []oauthButton
	for _, p := range a.providers {
		if p, ok := p.(*OAuthProvider); ok {
			out = append(out, oauthButton{
				ID:   p.ID(),
				Name: cmp.Or(p.Name(), p.ID()),
				URL:  DefaultBasePath + "/provider/" + url.PathEscape(p.ID()),
				Icon: providerIcon(p.ID(), cmp.Or(p.Name(), p.ID())),
			})
		}
	}
	return out
}

// credentialsProvider returns the first credentials provider, or nil when
// there is none or credentials sign-in is off.
func (a *Authorization) credentialsProvider() *CredentialsProvider {
	if a.endpoints.DisableCredentials {
		return nil
	}
	for _, p := range a.providers {
		if c, ok := p.(*CredentialsProvider); ok {
			return c
		}
	}
	return nil
}
