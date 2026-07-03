package goauth

import (
	"net/http"
	"strings"
)

// callbackTarget extracts the requested post-action redirect target from the
// form/query/cookie, defaulting to the origin.
func (a *Authorization) callbackTarget(r *http.Request, origin string) string {
	if v := r.FormValue("callbackUrl"); v != "" {
		return v
	}
	if v := r.URL.Query().Get("callbackUrl"); v != "" {
		return v
	}
	if v := readCookie(r, a.jar(strings.HasPrefix(origin, "https")).callbackURL().Name); v != "" {
		return v
	}
	return origin
}
