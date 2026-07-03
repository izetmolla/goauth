package goauth

import (
	jwtware "github.com/gofiber/contrib/v3/jwt"
	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
)

// GetClaims returns the jwt.MapClaims set by the JWT middleware. It
// errors out if no token is present or the claim type is unexpected.
func (a *Authorization) GetClaims(ctx fiber.Ctx) (jwt.MapClaims, error) {
	token := jwtware.FromContext(ctx)
	if token == nil {
		return nil, ErrMissingJWTContext
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}
	return claims, nil
}
