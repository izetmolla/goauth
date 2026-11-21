package goauth

import (
	"net"
	"net/http"
	"strings"
)

// Handler returns an http.Handler that serves every enabled goauth endpoint.
//
// API endpoints, under DefaultBasePath. On by default (switch off in
// Config.Endpoints):
//
//	GET  {base}/providers                      -> GetProviders
//	ANY  {base}/provider/{provider}            -> HandleSignIn (OAuth start, credentials sign-in)
//	ANY  {base}/provider/{provider}/callback   -> HandleCallback
//	GET  {base}/csrf                           -> GetCSRFToken
//
// Off by default (Endpoints.EnableRegister, Config.Verification):
//
//	POST {base}/provider/{provider}/register   -> HandleRegister
//	POST {base}/password/forgot                -> HandleForgotPassword
//	POST {base}/password/verify-code           -> HandleResetVerifyCode
//	POST {base}/password/reset                 -> HandleResetPassword
//	POST {base}/otp/send                       -> HandleOTPSend
//	POST {base}/otp/verify                     -> HandleOTPVerify
//	POST {base}/verify-email/send              -> HandleVerifyEmailSend
//	POST {base}/verify-email                   -> HandleVerifyEmail
//
// Off by default (Config.MFA.TOTP.Enabled):
//
//	GET  {base}/mfa/totp/status                -> HandleTOTPStatus
//	POST {base}/mfa/totp/enroll/begin          -> HandleTOTPEnrollBegin
//	POST {base}/mfa/totp/enroll/confirm        -> HandleTOTPEnrollConfirm
//	POST {base}/mfa/totp/disable               -> HandleTOTPDisable
//	POST {base}/mfa/totp/verify                -> HandleTOTPVerify
//
// Off by default (Config.LoginAs.Enabled):
//
//	GET|POST {base}/login_as?user_id=…         -> HandleLoginAs
//
// HTML pages, all off by default (Config.UI): sign-in, register, forgot
// password, one-time code and verify email, each at its configured path
// (UIOptions.SignInEndpoint, ...), plus GET {base}/assets/{file} for their
// CSS and JS. Pages outside DefaultBasePath must be routed to this handler
// as well.
//
// Endpoints that are off are not registered (they answer 404).
// It can be mounted on any router that speaks net/http, including Fiber via
// its adaptor middleware.
func (a *Authorization) Handler() http.Handler {
	mux := http.NewServeMux()
	base := DefaultBasePath
	e := a.endpoints
	route := func(pattern string, h http.HandlerFunc) { mux.HandleFunc(pattern, h) }
	page := func(name string, h http.HandlerFunc) {
		if p := a.pagePath(name); p != "" {
			mux.HandleFunc("GET "+p, h)
		}
	}

	if !e.DisableProviders {
		route("GET "+base+"/providers", a.GetProviders)
	}
	route(base+"/provider/{provider}", a.HandleSignIn)
	route(base+"/provider/{provider}/callback", a.HandleCallback)
	// Passkey / WebAuthn ceremonies (begin + finish for register and login).
	route("POST "+base+"/provider/{provider}/register/begin", a.HandlePasskey)
	route("POST "+base+"/provider/{provider}/register/finish", a.HandlePasskey)
	route("POST "+base+"/provider/{provider}/login/begin", a.HandlePasskey)
	route("POST "+base+"/provider/{provider}/login/finish", a.HandlePasskey)
	if !e.DisableCSRF {
		route("GET "+base+"/csrf", a.GetCSRFToken)
	}
	if a.registerProvider() != nil {
		route("POST "+base+"/provider/{provider}/register", a.HandleRegister)
	}
	if v := a.verify; v != nil {
		if v.reset.enabled {
			route("POST "+base+"/password/forgot", a.HandleForgotPassword)
			route("POST "+base+"/password/verify-code", a.HandleResetVerifyCode)
			route("POST "+base+"/password/reset", a.HandleResetPassword)
		}
		if v.otp.enabled {
			route("POST "+base+"/otp/send", a.HandleOTPSend)
			route("POST "+base+"/otp/verify", a.HandleOTPVerify)
		}
		if v.confirm.enabled {
			route("POST "+base+"/verify-email/send", a.HandleVerifyEmailSend)
			route("POST "+base+"/verify-email", a.HandleVerifyEmail)
		}
	}
	if a.totpEnabled() {
		route("GET "+base+"/mfa/totp/status", a.HandleTOTPStatus)
		route("POST "+base+"/mfa/totp/enroll/begin", a.HandleTOTPEnrollBegin)
		route("POST "+base+"/mfa/totp/enroll/confirm", a.HandleTOTPEnrollConfirm)
		route("POST "+base+"/mfa/totp/disable", a.HandleTOTPDisable)
		route("POST "+base+"/mfa/totp/verify", a.HandleTOTPVerify)
	}
	if a.loginAsEnabled() {
		route("GET "+base+"/login_as", a.HandleLoginAs)
		route("POST "+base+"/login_as", a.HandleLoginAs)
	}

	page(pageSignIn, a.SignInPage)
	page(pageRegister, a.RegisterPage)
	page(pageForgot, a.ForgotPasswordPage)
	page(pageOTP, a.OTPPage)
	page(pageVerify, a.VerifyEmailPage)
	if len(a.pages) > 0 {
		route("GET "+base+"/assets/{file}", serveAsset)
	}
	// Links in emails sent by v1.2.0 pointed here; send them to the page.
	if p := a.pagePath(pageForgot); p != "" && p != base+"/password/reset" {
		route("GET "+base+"/password/reset", a.ForgotPasswordPage)
	}
	if p := a.pagePath(pageOTP); p != "" && p != base+"/otp/verify" {
		route("GET "+base+"/otp/verify", a.OTPPage)
	}
	return mux
}

// providerIDFromRequest resolves the {provider} route parameter. It prefers
// http.ServeMux path values (Go 1.22+) and falls back to parsing the URL path
// so the handlers also work when mounted without a pattern-aware router.
func providerIDFromRequest(r *http.Request) string {
	if id := r.PathValue("provider"); id != "" {
		return id
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	for i, part := range parts {
		if part == "provider" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// isSecureRequest reports whether the request arrived over HTTPS, honoring the
// X-Forwarded-Proto header set by reverse proxies.
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// requestScheme returns "https" or "http" for the request (see isSecureRequest).
func requestScheme(r *http.Request) string {
	if isSecureRequest(r) {
		return "https"
	}
	return "http"
}

// clientIP returns the caller address, preferring proxy-forwarded headers.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip, _, _ := strings.Cut(fwd, ",")
		return strings.TrimSpace(ip)
	}
	if ip := r.Header.Get("X-Real-Ip"); ip != "" {
		return ip
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
