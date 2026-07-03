package goauth

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
)

// SetConnectResourceCookie stores the target resource id for a provider-connect OAuth round-trip.
func (a *Authorization) SetConnectResourceCookie(c fiber.Ctx, resourceID string) error {
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
	_, secure, err := a.origin(c)
	if err != nil {
		return err
	}
	setCookie(c, a.jar(secure).connectResource(), resourceID)
	return nil
}

func (a *Authorization) consumeConnectResourceCookie(c fiber.Ctx, jar *cookieJar) string {
	if jar == nil {
		return ""
	}
	resourceID := strings.TrimSpace(readCookie(c, jar.connectResource().Name))
	expireCookie(c, jar.connectResource())
	return resourceID
}
