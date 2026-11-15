package goauth

import (
	"cmp"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// CredentialsError is an error whose Message is safe to show to the user,
// such as "Invalid email or password" or "That email is already registered".
// Return it from CredentialsProvider.Authorize or Register; any other error
// is reported to the user as a generic failure.
type CredentialsError struct {
	Message string
	// Field optionally names the input the message is about, so the form
	// can focus it.
	Field string
}

func (e *CredentialsError) Error() string { return e.Message }

const (
	maxCredentialsBody  = 64 << 10
	maxCredentialsValue = 4 << 10

	codeCredentialsSignin = "CREDENTIALS_SIGNIN"
	codeRegisterFailed    = "REGISTER_FAILED"
	codeCSRF              = "CSRF"
	codeBadRequest        = "BAD_REQUEST"
	codeEmailNotVerified  = "EMAIL_NOT_VERIFIED"
	codeInvalidCode       = "INVALID_CODE"
	codeInvalidEmail      = "INVALID_EMAIL"
	codeWeakPassword      = "WEAK_PASSWORD"

	msgSomethingWrong = "Something went wrong. Please try again."
)

// Steps of the multi-step pages, and the names of the form fields the
// verification endpoints read.
const (
	stepRequest = "request"
	stepCode    = "code"
	stepLink    = "link"
	stepReset   = "reset"
	stepSent    = "sent"
	stepDone    = "done"

	fieldToken = "token"
	formSignIn = "signin"
	formReg    = "register"
	formForgot = "forgot"
	formOTP    = "otp"
	formVerify = "verify"

	keyStep = "step"
)

// Names of the built-in pages; their paths come from pagePath.
const (
	pageSignIn   = formSignIn
	pageRegister = formReg
	pageForgot   = formForgot
	pageOTP      = formOTP
	pageVerify   = formVerify
)

// formInput is a parsed form or JSON body.
type formInput struct {
	values    map[string]string // only the declared fields
	csrfToken string
	redirect  string // sanitized same-origin path, or ""
}

// isTokenFlow reports whether a request comes from a non-browser
// (mobile/API) client. Only the header counts: a cross-site form cannot set
// a custom header, so it cannot use this to skip the CSRF check.
func isTokenFlow(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("X-Auth-Flow"), "token")
}

// readForm parses a form-encoded or JSON body and keeps only the declared
// fields.
func readForm(w http.ResponseWriter, r *http.Request, fields []CredentialField) (formInput, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCredentialsBody)
	raw := map[string]string{}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct == "application/json" {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return formInput{}, errors.New("invalid JSON body")
		}
		for k, v := range body {
			if s, ok := v.(string); ok {
				raw[k] = s
			}
		}
	} else {
		if err := r.ParseForm(); err != nil {
			return formInput{}, errors.New("invalid form body")
		}
		for k := range r.PostForm {
			raw[k] = r.PostForm.Get(k)
		}
	}

	in := formInput{
		values:    make(map[string]string, len(fields)),
		csrfToken: raw["csrfToken"],
		redirect:  sanitizeRedirectPath(cmp.Or(raw["redirectUrl"], raw["callbackUrl"])),
	}
	for _, f := range fields {
		v := raw[f.Name]
		if len(v) > maxCredentialsValue {
			return formInput{}, errors.New(cmp.Or(f.Label, f.Name) + " is too long")
		}
		if f.Type != inputPassword {
			v = strings.TrimSpace(v)
		}
		in.values[f.Name] = v
	}
	return in, nil
}

// postForm runs the checks every state-changing endpoint shares: POST only,
// body parsing and the CSRF double-submit check (skipped for token-flow
// clients). It writes the error response and returns false on failure.
func (a *Authorization) postForm(w http.ResponseWriter, r *http.Request, page string, fields []CredentialField) (formInput, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		a.failure(w, r, page, http.StatusMethodNotAllowed, codeBadRequest, "Use POST", "")
		return formInput{}, false
	}
	_, secure, err := a.origin(r)
	if err != nil {
		a.failure(w, r, page, http.StatusInternalServerError, codeServerError, msgSomethingWrong, "")
		return formInput{}, false
	}
	in, err := readForm(w, r, fields)
	if err != nil {
		a.failure(w, r, page, http.StatusBadRequest, codeBadRequest, err.Error(), "")
		return formInput{}, false
	}
	if !isTokenFlow(r) && !verifyCSRF(readCookie(r, a.jar(secure).csrfToken().Name), in.csrfToken, a.JWTSecret) {
		a.failure(w, r, page, http.StatusForbidden, codeCSRF, "Your session expired. Reload the page and try again.", "")
		return formInput{}, false
	}
	return in, true
}

// credentialsCallback implements POST {base}/provider/{credentials}.
func (a *Authorization) credentialsCallback(w http.ResponseWriter, r *http.Request, p *CredentialsProvider) {
	if a.endpoints.DisableCredentials {
		notFound(w)
		return
	}
	a.handleCredentials(w, r, p, false)
}

// HandleRegister implements POST {base}/provider/{provider}/register: it
// creates an account with CredentialsProvider.Register and signs the new
// user in (or, with EmailConfirmation.RequireConfirmed, asks them to
// confirm their email first). Off unless Endpoints.EnableRegister is set.
func (a *Authorization) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		writeError(w, http.StatusInternalServerError, ErrNotInitialized.Error())
		return
	}
	p, ok := a.findProvider(providerIDFromRequest(r)).(*CredentialsProvider)
	if !ok || p.Register == nil || !a.endpoints.EnableRegister || a.endpoints.DisableCredentials {
		notFound(w)
		return
	}
	a.handleCredentials(w, r, p, true)
}

// handleCredentials runs the shared sign-in / sign-up pipeline.
func (a *Authorization) handleCredentials(w http.ResponseWriter, r *http.Request, p *CredentialsProvider, register bool) {
	page, fields, fn := pageSignIn, p.signInFields(), p.Authorize
	failCode, failMessage := codeCredentialsSignin, "Invalid credentials"
	if register {
		page, fields, fn = pageRegister, p.registerFields(), p.Register
		failCode, failMessage = codeRegisterFailed, "Could not create the account"
	}
	in, ok := a.postForm(w, r, page, fields)
	if !ok {
		return
	}
	if fn == nil {
		a.failure(w, r, page, http.StatusInternalServerError, codeServerError, "This sign-in method is not configured", "")
		return
	}

	user, err := fn(r.Context(), in.values, r)
	var ce *CredentialsError
	switch {
	case errors.As(err, &ce):
		a.failure(w, r, page, http.StatusUnauthorized, failCode, cmp.Or(ce.Message, failMessage), ce.Field)
		return
	case err != nil:
		// Not a user-facing error (database down, LDAP unreachable, ...):
		// never echo its text.
		a.failure(w, r, page, http.StatusInternalServerError, codeServerError, msgSomethingWrong, "")
		return
	case user == nil:
		a.failure(w, r, page, http.StatusUnauthorized, failCode, failMessage, "")
		return
	case user.ID == "":
		a.failure(w, r, page, http.StatusInternalServerError, codeServerError, msgSomethingWrong, "")
		return
	}

	if v := a.verify; v != nil && v.confirm.enabled {
		email := normalizeEmail(user.Email)
		if email != "" && !user.EmailVerified {
			required := v.opts.EmailConfirmation.RequireConfirmed
			if register || required {
				a.dispatchVerification(r, &v.confirm, email, true)
			}
			if required && register {
				a.stepResponse(w, r, pageRegister, stepSent, email,
					"Almost there! Check "+email+" to confirm your account.", a.codeExtras(&v.confirm))
				return
			}
			if required {
				a.failure(w, r, page, http.StatusForbidden, codeEmailNotVerified,
					"Please confirm your email first. We sent a new confirmation email to "+email+".", "")
				return
			}
		}
	}
	a.finishSignIn(w, r, page, user.ID, publicUser(user), p.ID(), in.redirect)
}

// finishSignIn creates the session and answers like the OAuth callback:
// JSON for fetch/token clients, otherwise the callback page, which stores
// the session in the browser and redirects.
func (a *Authorization) finishSignIn(w http.ResponseWriter, r *http.Request, page, userID string, user Map, method, redirect string) {
	tokens, sessionID, err := a.Authorize(append(
		[]AuthorizeOptionsFunc{a.WithUserID(userID)},
		a.SessionMetaFromRequest(r, method)...,
	)...)
	if err != nil {
		a.failure(w, r, page, http.StatusInternalServerError, codeServerError, msgSomethingWrong, "")
		return
	}
	tokenFlow := isTokenFlow(r)
	if !tokenFlow {
		a.SetSessionIDCookie(w, r, sessionID)
		if a.keepRefreshTokenServerSide {
			tokens.RefreshToken = ""
		}
	}
	payload := Map{
		payloadType:    "sign_in",
		"message":      "Signed in. Redirecting…",
		"user":         user,
		"tokens":       tokens,
		"session_id":   sessionID,
		"redirect_url": cmp.Or(redirect, a.defaultRedirect()),
	}
	if tokenFlow || wantsJSON(r) {
		writeJSON(w, http.StatusOK, payload)
		return
	}
	a.renderCallbackPage(w, payload)
}

// failure answers a failed request: JSON for fetch and token clients,
// otherwise a redirect back to the page (no-JS form posts) carrying only an
// error code, the step and the email.
func (a *Authorization) failure(w http.ResponseWriter, r *http.Request, page string, status int, code, message, field string) {
	path := a.pagePath(page)
	if isTokenFlow(r) || wantsJSON(r) || path == "" {
		body := Map{"message": message, "code": code}
		if field != "" {
			body["field"] = field
		}
		writeJSON(w, status, body)
		return
	}
	q := url.Values{"error": {code}}
	if step := r.PostFormValue(keyStep); step != "" {
		q.Set(keyStep, step)
	}
	if email := normalizeEmail(r.PostFormValue(inputEmail)); email != "" {
		q.Set(inputEmail, email)
	}
	http.Redirect(w, r, path+"?"+q.Encode(), http.StatusSeeOther)
}

// stepResponse moves a multi-step page forward: JSON for fetch clients, a
// redirect to the page at that step otherwise.
func (a *Authorization) stepResponse(w http.ResponseWriter, r *http.Request, page, step, email, message string, extra Map) {
	path := a.pagePath(page)
	if isTokenFlow(r) || wantsJSON(r) || path == "" {
		body := Map{payloadType: keyStep, keyStep: step, inputEmail: email, "message": message}
		for k, v := range extra {
			body[k] = v
		}
		writeJSON(w, http.StatusOK, body)
		return
	}
	q := url.Values{keyStep: {step}}
	if email != "" {
		q.Set(inputEmail, email)
	}
	http.Redirect(w, r, path+"?"+q.Encode(), http.StatusSeeOther)
}

// publicUser is the user shape returned to the browser after sign-in.
func publicUser(u *OAuthUser) Map {
	out := Map{"id": u.ID}
	if u.Email != "" {
		out[inputEmail] = u.Email
	}
	if name := cmp.Or(u.Name, strings.TrimSpace(u.FirstName+" "+u.LastName), u.NickName); name != "" {
		out["name"] = name
	}
	if img := cmp.Or(u.Image, u.AvatarURL); img != "" {
		out["image"] = img
	}
	return out
}

func (a *Authorization) defaultRedirect() string {
	return cmp.Or(a.ui.DefaultRedirect, "/")
}

// sanitizeRedirectPath turns a post-sign-in target into a same-origin path.
// Absolute URLs, protocol-relative "//host" and "/\host" forms are rejected
// so the page can never be used as an open redirect.
func sanitizeRedirectPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return ""
	}
	return u.RequestURI() + fragment(u)
}

func fragment(u *url.URL) string {
	if u.Fragment == "" {
		return ""
	}
	return "#" + u.EscapedFragment()
}
