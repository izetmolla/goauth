package goauth

import (
	"net"
	"net/http"
	"strings"
)

// Handler returns an http.Handler that serves every goauth endpoint under
// DefaultBasePath:
//
//	GET  {base}/providers                      -> GetProviders
//	ANY  {base}/provider/{provider}            -> HandleSignIn
//	ANY  {base}/provider/{provider}/callback   -> HandleCallback
//
// It can be mounted on any router that speaks net/http, including Fiber via
// its adaptor middleware.
func (a *Authorization) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+DefaultBasePath+"/providers", a.GetProviders)
	mux.HandleFunc(DefaultBasePath+"/provider/{provider}", a.HandleSignIn)
	mux.HandleFunc(DefaultBasePath+"/provider/{provider}/callback", a.HandleCallback)
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
