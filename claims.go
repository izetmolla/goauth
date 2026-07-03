package goauth

import (
	"context"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// jwtContextKey is the private context key under which the validated JWT is
// stored by UseAPIAuthorization.
type jwtContextKey struct{}

// withJWT returns a copy of ctx carrying the validated token.
func withJWT(ctx context.Context, token *jwt.Token) context.Context {
	return context.WithValue(ctx, jwtContextKey{}, token)
}

// JWTFromContext returns the validated JWT stored by the API middleware, or
// nil when the request was not authenticated.
func JWTFromContext(ctx context.Context) *jwt.Token {
	token, _ := ctx.Value(jwtContextKey{}).(*jwt.Token)
	return token
}

// GetClaims returns the jwt.MapClaims set by the JWT middleware. It
// errors out if no token is present or the claim type is unexpected.
func (a *Authorization) GetClaims(r *http.Request) (jwt.MapClaims, error) {
	token := JWTFromContext(r.Context())
	if token == nil {
		return nil, ErrMissingJWTContext
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}
	return claims, nil
}
