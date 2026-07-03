package goauth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// SetConnectResourceCookie stores the target resource id for a provider-connect OAuth round-trip.
func (a *Authorization) SetConnectResourceCookie(w http.ResponseWriter, r *http.Request, resourceID string) error {
	if a == nil {
		return ErrNotInitialized
	}
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		return errors.New("resource id is required")
	}
	if _, err := uuid.Parse(resourceID); err != nil {
		return errors.New("resource id must be a valid uuid")
	}
	_, secure, err := a.origin(r)
	if err != nil {
		return err
	}
	setCookie(w, a.jar(secure).connectResource(), resourceID)
	return nil
}

func (a *Authorization) consumeConnectResourceCookie(w http.ResponseWriter, r *http.Request, jar *cookieJar) string {
	if jar == nil {
		return ""
	}
	resourceID := strings.TrimSpace(readCookie(r, jar.connectResource().Name))
	expireCookie(w, jar.connectResource())
	return resourceID
}
