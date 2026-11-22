// Package common holds helpers shared by goauth and its provider
// subpackages: reading loosely typed JSON profiles, decoding ID tokens and
// calling provider APIs. It is internal to the goauth module.
package common

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MaxResponseBytes caps how much of a provider response is read, so a
// misbehaving endpoint cannot exhaust memory.
const MaxResponseBytes = 1 << 20

// HTTPClient is the client providers use for their own API calls. Unlike
// http.DefaultClient it has a timeout, so a stalled provider cannot hold a
// sign-in request open indefinitely. Tests may replace it.
var HTTPClient = &http.Client{Timeout: 15 * time.Second}

// DecodeJSON decodes a provider response body into v, reading at most
// MaxResponseBytes. A non-2xx status is returned as an error that includes
// the start of the body, prefixed with what.
func DecodeJSON(resp *http.Response, what string, v any) error {
	body := io.LimitReader(resp.Body, MaxResponseBytes)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(body)
		return fmt.Errorf("%s: status %d: %s", what, resp.StatusCode, b)
	}
	if err := json.NewDecoder(body).Decode(v); err != nil {
		return fmt.Errorf("%s: decode: %w", what, err)
	}
	return nil
}

// ErrInvalidIDToken is returned when DecodeIDTokenPayload cannot parse a JWT.
var ErrInvalidIDToken = errors.New("invalid id_token")

// String coerces a JSON scalar (as decoded from a userinfo/profile payload) into
// a string. OAuth providers are inconsistent about returning ids as numbers vs
// strings, so numeric kinds are handled too.
func String(v any) string {
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

// FirstNonEmpty returns the first non-empty string, or "".
func FirstNonEmpty(values ...string) string {
	return cmp.Or(values...)
}

// Values converts a flat string map into url.Values-shaped data for provider
// authorization parameters. It returns nil for an empty map.
func Values(m map[string]string) map[string][]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = []string{v}
	}
	return out
}

// Map returns v as map[string]any when it is one.
func Map(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// RawString reads key from a possibly-nil raw token map.
func RawString(raw map[string]any, key string) string {
	if raw == nil {
		return ""
	}
	return String(raw[key])
}

// NestedString reads a dotted path of map keys, e.g. "picture.data.url".
func NestedString(m map[string]any, path string) string {
	if m == nil || path == "" {
		return ""
	}
	cur := any(m)
	for key := range strings.SplitSeq(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[key]
	}
	return String(cur)
}

// DecodeIDTokenPayload decodes the JWT payload of an OIDC id_token without
// verifying the signature. Callers should only use this after a successful
// token exchange with the provider's token endpoint.
func DecodeIDTokenPayload(idToken string) (map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return nil, ErrInvalidIDToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some tokens are padded; try the padded variant.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, err
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// ProfileFields are the common claim names used across OAuth/OIDC providers.
type ProfileFields struct {
	ID    string
	Name  string
	Email string
	Image string
}

// MapUser extracts ID/Name/Email/Image from a raw profile using the usual
// Auth.js claim aliases (sub/id, name/login, email, picture/avatar_url, ...).
func MapUser(p map[string]any) ProfileFields {
	if p == nil {
		p = map[string]any{}
	}
	return ProfileFields{
		ID: FirstNonEmpty(
			String(p["sub"]),
			String(p["id"]),
			String(p["oid"]),
			String(p["user_id"]),
			String(p["account_id"]),
			String(p["uid"]),
		),
		Name: FirstNonEmpty(
			String(p["name"]),
			String(p["display_name"]),
			String(p["displayName"]),
			String(p["full_name"]),
			String(p["preferred_username"]),
			String(p["username"]),
			String(p["login"]),
			String(p["nickname"]),
			String(p["global_name"]),
		),
		Email: FirstNonEmpty(
			String(p["email"]),
			String(p["mail"]),
			String(p["userPrincipalName"]),
		),
		Image: FirstNonEmpty(
			String(p["picture"]),
			String(p["avatar_url"]),
			String(p["avatar"]),
			String(p["image"]),
			String(p["image_url"]),
			String(p["profile_image_url"]),
			String(p["profile_photo_url"]),
			NestedString(p, "picture.data.url"),
		),
	}
}
