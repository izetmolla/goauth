package goauth

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

const (
	// FlowIntentConnect marks an OAuth request that links extended provider scopes.
	FlowIntentConnect = "connect"
)

// errConnectIntentInvalid is returned when a connect-intent cookie is present
// but forged, malformed, or tied to a session that is no longer usable.
var errConnectIntentInvalid = errors.New("authorization: connect request is invalid or expired; start it again while signed in")

// connectIntent binds a provider-connect OAuth round-trip to the signed-in
// session that started it. The whole record is signed, so the callback can
// trust which user and resource the flow belongs to, no matter who completes
// the consent screen at the provider.
type connectIntent struct {
	UserID     string
	SessionID  string
	ResourceID string
}

// connectIntentFields is intent, user id, session id, resource id, signature.
const connectIntentFields = 5

func (c connectIntent) payload() string {
	return FlowIntentConnect + "|" + c.UserID + "|" + c.SessionID + "|" + c.ResourceID
}

// encode returns the signed cookie value. Ids containing the separator are
// rejected so a field can never spill into the next one.
func (c connectIntent) encode(secret string) (string, error) {
	for _, v := range []string{c.UserID, c.SessionID, c.ResourceID} {
		if strings.Contains(v, "|") {
			return "", errors.New("connect intent ids must not contain '|'")
		}
	}
	p := c.payload()
	return p + "|" + signValue(p, secret), nil
}

func decodeConnectIntent(value, secret string) (connectIntent, bool) {
	parts := strings.Split(value, "|")
	if len(parts) != connectIntentFields || parts[0] != FlowIntentConnect {
		return connectIntent{}, false
	}
	c := connectIntent{UserID: parts[1], SessionID: parts[2], ResourceID: parts[3]}
	if c.UserID == "" || c.SessionID == "" {
		return connectIntent{}, false
	}
	if subtle.ConstantTimeCompare([]byte(parts[4]), []byte(signValue(c.payload(), secret))) != 1 {
		return connectIntent{}, false
	}
	return c, true
}

// startConnectIntent requires a signed-in WEB session and stores a signed
// intent tying the connect flow to that session's user and the requested
// resource. Unauthenticated callers get ErrSessionNotFound.
func (a *Authorization) startConnectIntent(w http.ResponseWriter, r *http.Request, jar *cookieJar, resourceID string) error {
	if a.JWTSecret == "" {
		return errors.New("JWTSecret is required to sign flow intent")
	}
	session, err := a.GetSession(r.Context(), a.GetSessionID(r))
	if err != nil {
		return err
	}
	value, err := connectIntent{
		UserID:     session.UserID,
		SessionID:  session.ID,
		ResourceID: resourceID,
	}.encode(a.JWTSecret)
	if err != nil {
		return err
	}
	setCookie(w, jar.flowIntent(), value)
	return nil
}

// consumeConnectIntent reads and clears the connect-intent cookie. It returns
// present=false when the callback is a normal sign-in. When the cookie is
// present it must verify and its session must still be active and owned by
// the same user, otherwise errConnectIntentInvalid is returned.
func (a *Authorization) consumeConnectIntent(w http.ResponseWriter, r *http.Request, jar *cookieJar) (intent connectIntent, user *User, present bool, err error) {
	cookie := readCookie(r, jar.flowIntent().Name)
	expireCookie(w, jar.flowIntent())
	if cookie == "" {
		return connectIntent{}, nil, false, nil
	}
	intent, ok := decodeConnectIntent(cookie, a.JWTSecret)
	if !ok {
		return connectIntent{}, nil, true, errConnectIntentInvalid
	}
	session, err := a.GetSession(r.Context(), intent.SessionID)
	if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionExpired) {
		return connectIntent{}, nil, true, errConnectIntentInvalid
	}
	if err != nil {
		return connectIntent{}, nil, true, err
	}
	if session.UserID != intent.UserID {
		return connectIntent{}, nil, true, errConnectIntentInvalid
	}
	return intent, &User{ID: session.UserID, Roles: session.User.Roles}, true, nil
}

// SetFlowIntentCookie stores a signed, short-lived intent marker.
//
// Deprecated: connect flows are now bound to the signed-in session and are
// started only through the `?connect=1&resource_id=...` query parameters on
// the sign-in endpoint. A cookie set by this function is not honored as a
// connect intent.
func (a *Authorization) SetFlowIntentCookie(w http.ResponseWriter, r *http.Request, intent string) error {
	if a == nil {
		return ErrNotInitialized
	}
	if intent == "" {
		return errors.New("flow intent is required")
	}
	if a.JWTSecret == "" {
		return errors.New("JWTSecret is required to sign flow intent")
	}
	_, secure, err := a.origin(r)
	if err != nil {
		return err
	}
	setCookie(w, a.jar(secure).flowIntent(), intent+"|"+signValue(intent, a.JWTSecret))
	return nil
}
