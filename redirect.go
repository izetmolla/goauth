package goauth

import (
	"strings"

	"github.com/gofiber/fiber/v3"
)

// callbackTarget extracts the requested post-action redirect target from the
// form/query/cookie, defaulting to the origin.
func (a *Authorization) callbackTarget(c fiber.Ctx, origin string) string {
	if v := c.FormValue("callbackUrl"); v != "" {
		return v
	}
	if v := c.Query("callbackUrl"); v != "" {
		return v
	}
	if v := readCookie(c, a.jar(strings.HasPrefix(origin, "https")).callbackURL().Name); v != "" {
		return v
	}
	return origin
}
