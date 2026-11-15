package goauth

import (
	"net"
	"net/http"
	"strings"
)

// Handler returns an http.Handler that serves every enabled goauth endpoint
// under DefaultBasePath.
//
// Always on (switch off in Config.Endpoints):
//
//	GET  {base}/providers                      -> GetProviders
//	ANY  {base}/provider/{provider}            -> HandleSignIn (OAuth start, credentials sign-in)
//	ANY  {base}/provider/{provider}/callback   -> HandleCallback
//	GET  {base}/csrf                           -> GetCSRFToken
//	GET  {base}/signin                         -> SignInPage
//	GET  {base}/assets/{file}                  -> the pages' CSS/JS
//
// Off by default (Endpoints.EnableRegister, Config.Verification):
//
//	GET  {base}/register                       -> RegisterPage
//	POST {base}/provider/{provider}/register   -> HandleRegister
//	GET  {base}/forgot                         -> ForgotPasswordPage
//	POST {base}/password/forgot                -> HandleForgotPassword
//	GET  {base}/password/reset                 -> ForgotPasswordPage (reset link)
//	POST {base}/password/reset                 -> HandleResetPassword
//	GET  {base}/otp                            -> OTPPage
//	POST {base}/otp/send                       -> HandleOTPSend
//	GET  {base}/otp/verify                     -> OTPPage (magic link)
//	POST {base}/otp/verify                     -> HandleOTPVerify
//	GET  {base}/verify-email                   -> VerifyEmailPage (and its link)
//	POST {base}/verify-email                   -> HandleVerifyEmail
//	POST {base}/verify-email/send              -> HandleVerifyEmailSend
//
// Endpoints that are off are not registered (they answer 404).
// It can be mounted on any router that speaks net/http, including Fiber via
// its adaptor middleware.
func (a *Authorization) Handler() http.Handler {
	mux := http.NewServeMux()
	base := DefaultBasePath
	e := a.endpoints
	pages := !e.DisablePages
	route := func(pattern string, h http.HandlerFunc) { mux.HandleFunc(pattern, h) }
	page := func(pattern string, h http.HandlerFunc) {
		if pages {
			mux.HandleFunc(pattern, h)
		}
	}

	if !e.DisableProviders {
		route("GET "+base+"/providers", a.GetProviders)
	}
	route(base+"/provider/{provider}", a.HandleSignIn)
	route(base+"/provider/{provider}/callback", a.HandleCallback)
	if !e.DisableCSRF {
		route("GET "+base+"/csrf", a.GetCSRFToken)
	}
	page("GET "+base+"/signin", a.SignInPage)
	page("GET "+base+"/assets/{file}", serveAsset)

	if a.registerProvider() != nil {
		route("POST "+base+"/provider/{provider}/register", a.HandleRegister)
		page("GET "+base+pageRegister, a.RegisterPage)
	}
	if v := a.verify; v != nil {
		if v.reset.enabled {
			route("POST "+base+"/password/forgot", a.HandleForgotPassword)
			route("POST "+base+"/password/reset", a.HandleResetPassword)
			page("GET "+base+pageForgot, a.ForgotPasswordPage)
			page("GET "+base+"/password/reset", a.ForgotPasswordPage)
		}
		if v.otp.enabled {
			route("POST "+base+"/otp/send", a.HandleOTPSend)
			route("POST "+base+"/otp/verify", a.HandleOTPVerify)
			page("GET "+base+pageOTP, a.OTPPage)
			page("GET "+base+"/otp/verify", a.OTPPage)
		}
		if v.confirm.enabled {
			route("POST "+base+"/verify-email/send", a.HandleVerifyEmailSend)
			route("POST "+base+pageVerify, a.HandleVerifyEmail)
			page("GET "+base+pageVerify, a.VerifyEmailPage)
		}
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
