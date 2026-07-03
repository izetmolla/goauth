package goauth

import (
	"context"
	"encoding/json"
	"errors"
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
		return Tokens{}, "", errors.New("authorization is not initialized")
	}
	options := NewAuthorizeOptions(opts...)

	if options.userID != "" {
		if roles, err := a.getUserRolesFromDB(options.ctx, options.userID); err == nil {
			options.roles = roles
		}
	}

	if !json.Valid([]byte(options.content.ToString())) {
		return Tokens{}, "", errors.New("invalid content JSON payload")
	}
	if !json.Valid([]byte(options.roles.ToString())) {
		return Tokens{}, "", errors.New("invalid roles JSON payload")
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
