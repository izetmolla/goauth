package goauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	jwtware "github.com/gofiber/contrib/v3/jwt"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	"gorm.io/gorm"
)

func (a *Authorization) UseAPIAuthorization(opts ...AuthConfigOptions) fiber.Handler {
	uninitialized := func(c fiber.Ctx) error {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": ErrNotInitialized.Error(),
			"code":  "SERVER_ERROR",
		})
	}
	if a == nil {
		return uninitialized
	}

	cfg := NewAuthConfigOptions(opts...)

	jwtHandler := jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{Key: []byte(a.JWTSecret)},
		Extractor: extractors.Chain(
			extractors.FromAuthHeader("Bearer"),
			extractors.FromQuery("access_token"),
		),
		ErrorHandler: func(c fiber.Ctx, err error) error {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
				"code":  "UNAUTHORIZED",
			})
		},
		SuccessHandler: func(c fiber.Ctx) error {
			if len(cfg.roles) == 0 {
				return c.Next()
			}
			roles, err := a.GetRoles(c)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": err.Error(),
					"code":  "SERVER_ERROR",
				})
			}
			if hasRole, _, _ := a.GetRole(cfg.roles, roles); !hasRole {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": fmt.Sprintf("insufficient permissions: %s", strings.Join(cfg.roles, ", ")),
					"code":  "INSUFFICIENT_PERMISSIONS",
				})
			}
			return c.Next()
		},
	})

	if len(cfg.excludedPaths) == 0 {
		return jwtHandler
	}
	return func(c fiber.Ctx) error {
		if IsExcludedPath(cfg.excludedPaths, c.Path()) {
			return c.Next()
		}
		return jwtHandler(c)
	}
}

// UseWEBAuthorization returns a Fiber middleware that protects WEB
// routes with a session cookie. Missing or invalid cookies are
// redirected to the sign-in URL (preserving the original request URL
// in `redirectUrl`).
func (a *Authorization) UseWEBAuthorization(opts ...AuthConfigOptions) fiber.Handler {
	cfg := NewAuthConfigOptions(opts...)
	return func(c fiber.Ctx) error {
		if a == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": ErrNotInitialized.Error(),
				"code":  "SERVER_ERROR",
			})
		}
		if IsExcludedPath(cfg.excludedPaths, c.Path()) {
			return c.Next()
		}

		sessionID := c.Cookies(a.cookieSessionName)
		if sessionID == "" {
			return c.Redirect().Status(fiber.StatusTemporaryRedirect).To(a.getAuthRedirectURL(c))
		}

		session, err := a.GetSession(c.Context(), sessionID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return c.Redirect().Status(fiber.StatusTemporaryRedirect).To(a.getAuthRedirectURL(c))
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
				"code":  "SERVER_ERROR",
			})
		}

		if len(cfg.roles) > 0 {
			userRoles := FormatRoles(session.User.Roles)
			if hasRole, _, _ := a.GetRole(cfg.roles, userRoles); !hasRole {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": fmt.Sprintf("insufficient permissions: %s", strings.Join(cfg.roles, ", ")),
					"code":  "INSUFFICIENT_PERMISSIONS",
				})
			}
		}
		return c.Next()
	}
}

// getAuthRedirectURL builds the sign-in URL with a `redirectUrl` query
// parameter pointing back at the original request, preserving the
// browser scheme.
func (a *Authorization) getAuthRedirectURL(c fiber.Ctx) string {
	scheme := "http"
	if c.Protocol() == "https" || c.Secure() {
		scheme = "https"
	}
	original := fmt.Sprintf("%s://%s%s", scheme, c.Hostname(), c.OriginalURL())
	return fmt.Sprintf("%s?redirectUrl=%s", a.signInRedirectURL, url.QueryEscape(original))
}
