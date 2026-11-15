package goauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
)

// CSRF protection uses the signed double-submit cookie pattern from Auth.js: the
// cookie stores "<token>|<hmac>" where hmac = HMAC-SHA256(token + secret). The
// same raw token must be echoed in the request body for unsafe (POST) actions.

// signValue returns the hex HMAC-SHA256 used to sign cookie values (CSRF
// token, flow intent). The value+secret message layout matches Auth.js and
// must not change, or previously issued cookies stop verifying.
func signValue(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value + secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyCSRF reports whether the signed cookie is authentic and the submitted
// body token matches it. An empty body token never validates.
func verifyCSRF(cookieValue, bodyToken, secret string) bool {
	token, sig, ok := strings.Cut(cookieValue, "|")
	return ok && bodyToken != "" &&
		subtle.ConstantTimeCompare([]byte(sig), []byte(signValue(token, secret))) == 1 &&
		subtle.ConstantTimeCompare([]byte(bodyToken), []byte(token)) == 1
}

// ensureCSRFToken returns the raw token from the request's CSRF cookie when
// that cookie is authentic, otherwise issues a fresh signed cookie. Reusing
// a valid token keeps several open tabs working at once.
func (a *Authorization) ensureCSRFToken(w http.ResponseWriter, r *http.Request, secure bool) string {
	opt := a.jar(secure).csrfToken()
	if v := readCookie(r, opt.Name); v != "" {
		if token, sig, ok := strings.Cut(v, "|"); ok && token != "" &&
			subtle.ConstantTimeCompare([]byte(sig), []byte(signValue(token, a.JWTSecret))) == 1 {
			return token
		}
	}
	token := randomString(32)
	setCookie(w, opt, token+"|"+signValue(token, a.JWTSecret))
	return token
}

// GetCSRFToken implements GET {base}/csrf for single-page apps that build
// their own credentials form: it sets the CSRF cookie and returns the token
// to send back as the csrfToken field.
func (a *Authorization) GetCSRFToken(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		writeError(w, http.StatusInternalServerError, ErrNotInitialized.Error())
		return
	}
	if a.endpoints.DisableCSRF {
		notFound(w)
		return
	}
	_, secure, err := a.origin(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get origin")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, Map{"csrfToken": a.ensureCSRFToken(w, r, secure)})
}
