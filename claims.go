package goauth

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

// accessClaims is the slim, typed view of an access token used on the hot
// path. Decoding into a struct instead of jwt.MapClaims avoids building a
// map[string]any (and boxing every value) on every API request; claims the
// middleware does not need, such as "content", are skipped by the decoder.
type accessClaims struct {
	UserID    string          `json:"user_id"`
	TokenType string          `json:"token_type,omitempty"`
	SessionID string          `json:"session_id,omitempty"`
	Roles     json.RawMessage `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// isRefresh reports whether the claims belong to a refresh token. Tokens
// minted before the token_type claim existed are recognized by session_id,
// which only refresh tokens carry.
func (c *accessClaims) isRefresh() bool {
	switch c.TokenType {
	case tokenTypeRefresh:
		return true
	case tokenTypeAccess:
		return false
	default:
		return c.SessionID != ""
	}
}

// apiPrincipal is what UseAPIAuthorization stores on the request context.
// Roles and the jwt.MapClaims view are computed at most once, and only when
// something asks for them.
type apiPrincipal struct {
	token  *jwt.Token // verified; Claims is *accessClaims
	claims *accessClaims

	rolesOnce sync.Once
	roles     []string
	rolesErr  error

	mapOnce  sync.Once
	mapToken *jwt.Token
}

// Roles returns the decoded role grants, decoding them on first use.
func (p *apiPrincipal) Roles() ([]string, error) {
	p.rolesOnce.Do(func() {
		p.roles, p.rolesErr = rolesFromJSON(p.claims.Roles)
	})
	return p.roles, p.rolesErr
}

// mapClaimsToken returns the verified token with jwt.MapClaims claims, the
// shape GetClaims and JWTFromContext have always exposed. The payload was
// already verified, so it is only decoded here, once.
func (p *apiPrincipal) mapClaimsToken() *jwt.Token {
	p.mapOnce.Do(func() {
		t, _, err := jwt.NewParser().ParseUnverified(p.token.Raw, jwt.MapClaims{})
		if err != nil {
			return
		}
		t.Signature = p.token.Signature
		t.Valid = true
		p.mapToken = t
	})
	return p.mapToken
}

// principalContextKey is the private context key for *apiPrincipal.
type principalContextKey struct{}

func withPrincipal(ctx context.Context, p *apiPrincipal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}

func principalFrom(ctx context.Context) *apiPrincipal {
	p, _ := ctx.Value(principalContextKey{}).(*apiPrincipal)
	return p
}

// JWTFromContext returns the validated JWT stored by the API middleware, or
// nil when the request was not authenticated. Its Claims are jwt.MapClaims.
func JWTFromContext(ctx context.Context) *jwt.Token {
	if p := principalFrom(ctx); p != nil {
		return p.mapClaimsToken()
	}
	return nil
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

// authDataContextKey is the private context key for the AuthData stored by
// UseWEBAuthorization.
type authDataContextKey struct{}

func withAuthData(ctx context.Context, data AuthData) context.Context {
	return context.WithValue(ctx, authDataContextKey{}, data)
}

// AuthDataFromContext returns the principal stored by UseWEBAuthorization,
// and whether one was stored.
func AuthDataFromContext(ctx context.Context) (AuthData, bool) {
	data, ok := ctx.Value(authDataContextKey{}).(AuthData)
	return data, ok
}
