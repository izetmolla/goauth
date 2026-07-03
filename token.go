package goauth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
)

// Claims are the JWT claims embedded in access tokens.
type Claims struct {
	UserID  string     `json:"user_id"`
	Content JSONBAny   `json:"content"`
	Roles   JSONBArray `json:"roles"`
	jwt.RegisteredClaims
}

// RefreshTokenClaims are the JWT claims embedded in refresh tokens.
type RefreshTokenClaims struct {
	SessionID           string     `json:"session_id"`
	UserID              string     `json:"user_id"`
	AccessTokenLifetime string     `json:"tokenlife,omitempty"`
	SigningMethodHMAC   string     `json:"signing_method,omitempty"`
	Content             JSONBAny   `json:"content,omitempty"`
	Roles               JSONBArray `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// Tokens groups the access/refresh pair returned to clients.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// --- Header & token parsing ----------------------------------------------

// GetTokenFromHeader strips the "Bearer "/"Token " scheme from an
// Authorization header value. Returns the value as-is if no scheme is set
// and an error when the header is empty.
func (a *Authorization) GetTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("authorization header is required")
	}
	switch {
	case len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer "):
		return authHeader[7:], nil
	case len(authHeader) > 6 && strings.EqualFold(authHeader[:6], "Token "):
		return authHeader[6:], nil
	default:
		return authHeader, nil
	}
}

// ExtractToken parses and validates a refresh token, returning its claims.
func (a *Authorization) ExtractToken(tokenString string) (*RefreshTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, a.keyFunc)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

func (a *Authorization) keyFunc(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return []byte(a.JWTSecret), nil
}

// RefreshAccessToken issues a new access token from a previously-validated
// refresh-token claims set and the matching session row.
//
// Extra functional options can be passed to override the embedded content.
func (a *Authorization) RefreshAccessToken(
	refreshTokenClaims *RefreshTokenClaims,
	sessionData *Session,
	opts ...AuthorizeOptionsFunc,
) (string, error) {
	if a == nil {
		return "", errors.New("authorization is not initialized")
	}
	options := NewAuthorizeOptions(opts...)
	if refreshTokenClaims == nil {
		return "", errors.New("refresh token claims are required")
	}
	if sessionData == nil {
		return "", errors.New("session data is required")
	}

	accessTokenDuration, err := ParseCustomDuration(a.accessTokenDuration, DefaultAccessTokenDuration)
	if err != nil {
		return "", err
	}

	now := time.Now()
	roles := sessionData.User.Roles
	if roles == nil {
		roles = JSONBArray([]any{})
	}

	claims := &Claims{
		UserID:  refreshTokenClaims.UserID,
		Content: options.content,
		Roles:   roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	return jwt.NewWithClaims(resolveSigningMethod(a.signingMethod), claims).SignedString([]byte(a.JWTSecret))
}

// --- Token issuance -------------------------------------------------------

// signTokenPair signs an access and a refresh token in one shot.
// Time.Now() is called once and reused so the lifetimes line up exactly.
func (a *Authorization) SignTokenPair(o *AuthorizeOptions, sessionID string) (string, string, error) {
	if a == nil {
		return "", "", errors.New("authorization is not initialized")
	}
	if o == nil {
		return "", "", errors.New("authorize options are required")
	}
	if sessionID == "" {
		return "", "", errors.New("session ID is required")
	}

	now := time.Now()

	accessTokenDuration, err := ParseCustomDuration(a.accessTokenDuration, DefaultAccessTokenDuration)
	if err != nil {
		return "", "", err
	}
	accessClaims := &Claims{
		UserID:  o.userID,
		Content: o.content,
		Roles:   o.roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	accessToken, err := jwt.NewWithClaims(resolveSigningMethod(a.signingMethod), accessClaims).SignedString([]byte(a.JWTSecret))
	if err != nil {
		return "", "", fmt.Errorf("sign access token: %w", err)
	}
	refreshTokenDuration, err := ParseCustomDuration(a.refreshTokenDuration, DefaultRefreshTokenDuration)
	if err != nil {
		return "", "", err
	}
	refreshClaims := &RefreshTokenClaims{
		SessionID:           sessionID,
		UserID:              o.userID,
		AccessTokenLifetime: refreshTokenDuration.String(),
		SigningMethodHMAC:   a.signingMethod,
		Content:             o.content,
		Roles:               o.roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(refreshTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	refreshToken, err := jwt.NewWithClaims(resolveSigningMethod(a.signingMethod), refreshClaims).SignedString([]byte(a.JWTSecret))
	if err != nil {
		return "", "", fmt.Errorf("sign refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// other for Social Login
// wantsTokens reports whether the response should be tokens (JSON) rather than a
// session cookie + redirect.
func (a *Authorization) wantsTokens(c fiber.Ctx) bool {
	//Need to implement this
	// if !a.cfg.Tokens.Enabled {
	// 	return false
	// }
	// if a.cfg.Tokens.AlwaysReturn {
	// 	return true
	// }
	return strings.EqualFold(c.Get("X-Auth-Flow"), "token") || c.Query("flow") == "token"
}

// checkCSRF validates the signed double-submit token for unsafe actions.
func (a *Authorization) checkCSRF(c fiber.Ctx, secure bool) bool {
	jar := a.jar(secure)
	cookieVal := readCookie(c, jar.csrfToken().Name)
	body := c.FormValue("csrfToken")
	_, ok := verifyCSRF(cookieVal, body, a.JWTSecret)
	return ok
}
