package goauth

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

const (
	// FlowIntentConnect marks an OAuth request that links extended provider scopes.
	FlowIntentConnect = "connect"
)

func signedFlowIntentValue(intent, secret string) string {
	return intent + "|" + signValue(intent, secret)
}

func verifyFlowIntentCookie(cookieValue, intent, secret string) bool {
	got, sig, ok := strings.Cut(cookieValue, "|")
	if !ok || got != intent {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sig), []byte(signValue(intent, secret))) == 1
}

// SetFlowIntentCookie stores a signed, short-lived intent marker for the OAuth round-trip.
func (a *Authorization) SetFlowIntentCookie(w http.ResponseWriter, r *http.Request, intent string) error {
	if a == nil {
		return ErrNotInitialized
	}
	if intent == "" {
		return errors.New("flow intent is required")
	}
	if a.JWTSecret == "" {
		return errors.New("JWTSecret is required to sign flow intent")
	}
	_, secure, err := a.origin(r)
	if err != nil {
		return err
	}
	setCookie(w, a.jar(secure).flowIntent(), signedFlowIntentValue(intent, a.JWTSecret))
	return nil
}

func (a *Authorization) consumeFlowIntent(w http.ResponseWriter, r *http.Request, jar *cookieJar, intent string) bool {
	if a == nil || jar == nil || intent == "" || a.JWTSecret == "" {
		return false
	}
	cookie := readCookie(r, jar.flowIntent().Name)
	expireCookie(w, jar.flowIntent())
	if cookie == "" {
		return false
	}
	return verifyFlowIntentCookie(cookie, intent, a.JWTSecret)
}
