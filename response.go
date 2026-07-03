package goauth

import (
	"github.com/gofiber/fiber/v3"
)

// wantsJSON reports whether the client prefers a JSON response over a redirect.
func wantsJSON(c fiber.Ctx) bool {
	accept := c.Get("Accept")
	if accept == "application/json" {
		return true
	}
	return c.Get("X-Auth-Return-Redirect") == "1" || c.Query("json") == "true"
}

// redirectOrJSON either issues an HTTP redirect or returns the target URL as
// JSON, matching the Auth.js client convention (X-Auth-Return-Redirect).
func (a *Authorization) redirectOrJSON(c fiber.Ctx, target string) error {
	if wantsJSON(c) {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"url": target})
	}
	return c.Redirect().Status(fiber.StatusFound).To(target)
}
