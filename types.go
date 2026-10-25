package goauth

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// Profile is the raw, provider-specific user payload returned from an OAuth/OIDC
// userinfo endpoint or decoded ID token. Providers map it into a User via their
// Profile function.
type Profile map[string]any

// Account links a User to a provider login. For OAuth/OIDC providers it holds the
// issued tokens; this mirrors the Auth.js `Account` model used by adapters.
type Account struct {
	UserID            string `json:"userId,omitempty"`
	Type              string `json:"type"`
	Provider          string `json:"provider"`
	ProviderAccountID string `json:"providerAccountId"`

	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	Scope        string `json:"scope,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	SessionState string `json:"session_state,omitempty"`
}

// TokenSet is the response of an OAuth 2.0 / OIDC token endpoint.
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`

	// Raw preserves every field returned by the provider, including
	// non-standard ones, so callbacks can read them.
	Raw map[string]any `json:"-"`
}

// ExpiresAt converts the relative expires_in into an absolute unix timestamp.
func (t TokenSet) ExpiresAt() int64 {
	if t.ExpiresIn <= 0 {
		return 0
	}
	return time.Now().Add(time.Duration(t.ExpiresIn) * time.Second).Unix()
}

// asString coerces common JSON scalar types into a string. OAuth providers are
// inconsistent about returning ids as numbers vs strings.
func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case bool:
		return strconv.FormatBool(x)
	default:
		return ""
	}
}

// JSONBAny is a JSON object stored in a PostgreSQL jsonb column.
type JSONBAny map[string]any

func (a JSONBAny) Value() (driver.Value, error) {
	if a == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(a)
}

func (a *JSONBAny) Scan(value any) error {
	if value == nil {
		*a = JSONBAny{}
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("failed to scan JSONBAny: unsupported type %T", value)
	}
	if len(bytes) == 0 || string(bytes) == "null" {
		*a = JSONBAny{}
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(bytes, &out); err != nil {
		return err
	}
	*a = JSONBAny(out)
	return nil
}

// ToString returns the JSON encoding of a, or "{}" if it cannot be encoded.
func (a JSONBAny) ToString() string {
	b, err := json.Marshal(a)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// JSONBArray is a JSON array stored in a jsonb column, e.g. a user's role
// grants ("admin:rw").
type JSONBArray []any

func (JSONBArray) GormDataType() string {
	return "json"
}

func (a JSONBArray) Value() (driver.Value, error) {
	if a == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(a)
}

func (a *JSONBArray) Scan(value any) error {
	if value == nil {
		*a = nil
		return nil
	}
	var raw []byte
	switch v := value.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("invalid JSONBArray type %T", value)
	}
	if len(raw) == 0 {
		*a = JSONBArray{}
		return nil
	}
	return json.Unmarshal(raw, a)
}

// ToString returns the JSON encoding of a, or "[]" if it cannot be encoded.
func (a JSONBArray) ToString() string {
	b, err := json.Marshal(a)
	if err != nil {
		return "[]"
	}
	return string(b)
}
