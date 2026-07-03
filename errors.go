package goauth

import "errors"

var (
	ErrNotInitialized = errors.New("authorization: not initialized")

	// Token & session errors.
	ErrMissingJWTContext   = errors.New("authorization: missing jwt token in context")
	ErrInvalidClaims       = errors.New("authorization: invalid claims")
	ErrInvalidRoles        = errors.New("authorization: invalid roles")
	ErrMissingRefreshToken = errors.New("authorization: refresh token is required")
	ErrInvalidRefreshToken = errors.New("authorization: invalid refresh token")
	ErrSessionNotFound     = errors.New("authorization: session not found")
	ErrSessionExpired      = errors.New("authorization: session expired")
)
