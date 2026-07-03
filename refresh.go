package goauth

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

// HandleRefreshToken is a middleware that conditionally modules
// refresh-token requests. The request is only handled when the client
// opts in by setting the RefreshTokenHandlerIdentifier header; every
// other request is forwarded to the next handler.
//
// On success the response body is the new access token; on failure a
// JSON envelope with an error message and machine-readable code is
// returned.
func (a *Authorization) HandleRefreshToken(c fiber.Ctx) error {
	if a == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": ErrNotInitialized.Error(),
			"code":  "SERVER_ERROR",
		})
	}
	ctx := c.Context()
	if c.Get(RefreshTokenHandlerIdentifier, "no") == "no" {
		return c.Next()
	}

	refreshToken, err := a.GetTokenFromHeader(c.Get("Authorization"))
	if err != nil {
		refreshToken = bodyRefreshToken(c)
	}
	if refreshToken == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": ErrMissingRefreshToken.Error(),
			"code":  "TOKEN_INVALID",
		})
	}

	claims, err := a.ExtractToken(refreshToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
			"code":  "TOKEN_INVALID",
		})
	}

	session, err := a.GetSession(ctx, claims.SessionID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": ErrSessionNotFound.Error(),
				"code":  "UNAUTHORIZED",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
			"code":  "SERVER_ERROR",
		})
	}

	accessToken, err := a.RefreshAccessToken(claims, session)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
			"code":  "SERVER_ERROR",
		})
	}

	return c.Status(fiber.StatusOK).JSON(accessToken)
}

// bodyRefreshToken pulls a refresh token out of the JSON body. Errors
// are swallowed: an absent body simply means "no fallback available".
func bodyRefreshToken(c fiber.Ctx) string {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.Bind().Body(&body); err != nil {
		return ""
	}
	return body.RefreshToken
}
