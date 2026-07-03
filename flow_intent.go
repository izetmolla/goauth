package goauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v3"
)

const (
	// FlowIntentConnect marks an OAuth request that links extended provider scopes.
	FlowIntentConnect = "connect"
)

func flowIntentHash(intent, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(intent + secret))
	return hex.EncodeToString(mac.Sum(nil))
}

func signedFlowIntentValue(intent, secret string) string {
	return intent + "|" + flowIntentHash(intent, secret)
}

func verifyFlowIntentCookie(cookieValue, intent, secret string) bool {
	parts := strings.SplitN(cookieValue, "|", 2)
	if len(parts) != 2 || parts[0] != intent {
		return false
	}
	expected := flowIntentHash(intent, secret)
	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) == 1
}

// SetFlowIntentCookie stores a signed, short-lived intent marker for the OAuth round-trip.
func (a *Authorization) SetFlowIntentCookie(c fiber.Ctx, intent string) error {
	if a == nil {
		return ErrNotInitialized
	}
	if intent == "" {
		return errors.New("flow intent is required")
	}
	if a.JWTSecret == "" {
		return errors.New("JWTSecret is required to sign flow intent")
	}
	_, secure, err := a.origin(c)
	if err != nil {
		return err
	}
	setCookie(c, a.jar(secure).flowIntent(), signedFlowIntentValue(intent, a.JWTSecret))
	return nil
}

func (a *Authorization) consumeFlowIntent(c fiber.Ctx, jar *cookieJar, intent string) bool {
	if a == nil || jar == nil || intent == "" || a.JWTSecret == "" {
		return false
	}
	cookie := readCookie(c, jar.flowIntent().Name)
	expireCookie(c, jar.flowIntent())
	if cookie == "" {
		return false
	}
	return verifyFlowIntentCookie(cookie, intent, a.JWTSecret)
}
