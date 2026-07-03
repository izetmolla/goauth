// Package common holds helpers shared by the provider preset subpackages
// (google, github, apple, oauth, oidc, ...). It is internal: only packages under
// goauth/providers may import it.
package common

import "strconv"

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
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
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
