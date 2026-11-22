package goauth

import "errors"

// Errors returned by goauth. Match them with errors.Is: several are wrapped
// with more detail.
var (
	// ErrNotInitialized is returned when a method is called on a nil *Authorization.
	ErrNotInitialized = errors.New("authorization: not initialized")

	// ErrMissingJWTContext means the request did not pass through
	// UseAPIAuthorization, so it carries no validated token.
	ErrMissingJWTContext = errors.New("authorization: missing jwt token in context")
	// ErrInvalidClaims means the validated token has an unexpected claims type.
	ErrInvalidClaims = errors.New("authorization: invalid claims")
	// ErrInvalidRoles means the roles claim is missing or malformed.
	ErrInvalidRoles = errors.New("authorization: invalid roles")
	// ErrMissingRefreshToken means a refresh request carried no refresh token.
	ErrMissingRefreshToken = errors.New("authorization: refresh token is required")
	// ErrInvalidRefreshToken means the refresh token failed validation or does
	// not belong to its session's user.
	ErrInvalidRefreshToken = errors.New("authorization: invalid refresh token")
	// ErrSessionNotFound means the session id is empty, unknown or signed
	// out, or its user no longer exists.
	ErrSessionNotFound = errors.New("authorization: session not found")
	// ErrSessionExpired means the session is past its expiry.
	ErrSessionExpired = errors.New("authorization: session expired")
)
