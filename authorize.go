package goauth

import (
	"context"
	"encoding/json"
	"fmt"
)

// --- Authorize options ----------------------------------------------------

// AuthorizeOptions carries every input required to issue a new token pair.
// Build it via functional options (WithUserID, WithRoles, ...).
type AuthorizeOptions struct {
	ctx       context.Context
	userID    string
	account   *Account
	ipAddress string
	userAgent string
	content   JSONBAny
	roles     JSONBArray
	method    string
}

// AuthorizeOptionsFunc is the functional-option type used with Authorize,
// RefreshAccessToken and the low-level token generators.
type AuthorizeOptionsFunc func(*AuthorizeOptions)

func defaultAuthorizeOptions() AuthorizeOptions {
	return AuthorizeOptions{
		ctx:     context.Background(),
		roles:   JSONBArray([]any{}),
		content: JSONBAny(map[string]any{}),
		method:  "credentials",
	}
}

// NewAuthorizeOptions applies the provided functional options on top of
// the defaults and returns a populated AuthorizeOptions struct.
func NewAuthorizeOptions(opts ...AuthorizeOptionsFunc) *AuthorizeOptions {
	o := defaultAuthorizeOptions()
	for _, fn := range opts {
		if fn != nil {
			fn(&o)
		}
	}
	return &o
}

// Authorize creates a fresh session row and signs an access/refresh token
// pair for it.
//
// It returns the token pair, the new session id and an error, if any.
func (a *Authorization) Authorize(opts ...AuthorizeOptionsFunc) (Tokens, string, error) {
	if a == nil {
		return Tokens{}, "", ErrNotInitialized
	}
	options := NewAuthorizeOptions(opts...)

	if options.userID != "" {
		if roles, err := a.getUserRolesFromDB(options.ctx, options.userID); err == nil {
			options.roles = roles
		}
	}

	// ToString swallows marshal errors (returning "{}"/"[]"), so validate by
	// marshaling directly.
	if _, err := json.Marshal(options.content); err != nil {
		return Tokens{}, "", fmt.Errorf("invalid content JSON payload: %w", err)
	}
	if _, err := json.Marshal(options.roles); err != nil {
		return Tokens{}, "", fmt.Errorf("invalid roles JSON payload: %w", err)
	}

	sessionID, err := a.CreateSession(options)
	if err != nil {
		return Tokens{}, "", fmt.Errorf("create session: %w", err)
	}

	accessToken, refreshToken, err := a.SignTokenPair(options, sessionID)
	if err != nil {
		return Tokens{}, "", err
	}

	return Tokens{AccessToken: accessToken, RefreshToken: refreshToken}, sessionID, nil
}
