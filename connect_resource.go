package goauth

import (
	"errors"
	"net/http"
	"strings"
	"uuid"
)

// validateConnectResourceID trims and checks a connect-flow resource id. An
// empty id is allowed (OnProviderConnect is then not called).
func validateConnectResourceID(resourceID string) (string, error) {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		return "", nil
	}
	if _, err := uuid.Parse(resourceID); err != nil {
		return "", errors.New("resource id must be a valid uuid")
	}
	return resourceID, nil
}

// SetConnectResourceCookie stores the target resource id for a provider-connect OAuth round-trip.
//
// Deprecated: the resource id is now part of the signed connect intent, which
// is created from the `?connect=1&resource_id=...` query parameters on the
// sign-in endpoint. A cookie set by this function is ignored.
func (a *Authorization) SetConnectResourceCookie(w http.ResponseWriter, r *http.Request, resourceID string) error {
	if a == nil {
		return ErrNotInitialized
	}
	resourceID, err := validateConnectResourceID(resourceID)
	if err != nil {
		return err
	}
	if resourceID == "" {
		return errors.New("resource id is required")
	}
	_, secure, err := a.origin(r)
	if err != nil {
		return err
	}
	setCookie(w, a.jar(secure).connectResource(), resourceID)
	return nil
}
