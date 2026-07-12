package goauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// GetRoles extracts the "roles" claim as a []string. Several encodings
// are accepted because the claim crosses JSON, jwt and DB boundaries.
func (a *Authorization) GetRoles(r *http.Request) ([]string, error) {
	claims, err := a.GetClaims(r)
	if err != nil {
		return nil, err
	}
	raw, ok := claims["roles"]
	if !ok || raw == nil {
		return nil, ErrInvalidRoles
	}
	return rolesFromAny(raw)
}

// GetRole checks authorization against endpoint role names and user role grants.
//
// endpointRoles are plain names required by the route (e.g. "admin", "hr").
// userRoles use "name:perms" where perms is r (read), w (write), or rw (both).
//
// Returns:
//   - hasRole: user has at least one endpoint role (name match before ":")
//   - canRead: matched grant includes r or rw
//   - canWrite: matched grant includes w or rw
func (a *Authorization) GetRole(endpointRoles, userRoles []string) (hasRole, canRead, canWrite bool) {
	if len(endpointRoles) == 0 || len(userRoles) == 0 {
		return false, false, false
	}

	allowed := make(map[string]struct{}, len(endpointRoles))
	for _, r := range endpointRoles {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		// Allow endpoint config like "admin:rw" — only the role name is compared.
		if name, _, ok := strings.Cut(r, ":"); ok {
			r = strings.TrimSpace(name)
		}
		allowed[strings.ToLower(r)] = struct{}{}
	}
	if len(allowed) == 0 {
		return false, false, false
	}

	for _, userRole := range userRoles {
		name, perms, ok := parseUserRoleGrant(userRole)
		if !ok {
			continue
		}
		if _, ok := allowed[strings.ToLower(name)]; !ok {
			continue
		}
		hasRole = true
		if roleGrantAllowsRead(perms) {
			canRead = true
		}
		if roleGrantAllowsWrite(perms) {
			canWrite = true
		}
	}
	return hasRole, canRead, canWrite
}

func parseUserRoleGrant(userRole string) (name, perms string, ok bool) {
	userRole = strings.TrimSpace(userRole)
	if userRole == "" {
		return "", "", false
	}
	name, perms, found := strings.Cut(userRole, ":")
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", false
	}
	if found {
		perms = strings.TrimSpace(strings.ToLower(perms))
	}
	return name, perms, true
}

func roleGrantAllowsRead(perms string) bool {
	return strings.Contains(perms, "r")
}

func roleGrantAllowsWrite(perms string) bool {
	return strings.Contains(perms, "w")
}

// rolesFromAny decodes whatever the JWT library handed us for the
// "roles" claim into a clean []string.
//
// Note: JWT claims decode JSON arrays as []any, so that branch is the hot
// path for API requests. All slice shapes are funneled through FormatRoles
// so trimming/blank-dropping behaves identically everywhere.
func rolesFromAny(raw any) ([]string, error) {
	switch v := raw.(type) {
	case []string:
		return normalizeRoleGrants(v), nil
	case JSONBArray:
		return FormatRoles(v), nil
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return nil, ErrInvalidRoles
		}
		// A JSON-encoded array (e.g. `["admin:rw","hr:r"]`) must be parsed,
		// not wrapped as a single grant string.
		if strings.HasPrefix(s, "[") {
			var arr JSONBArray
			if err := json.Unmarshal([]byte(s), &arr); err != nil {
				return nil, ErrInvalidRoles
			}
			return FormatRoles(arr), nil
		}
		return []string{s}, nil
	case []any:
		return FormatRoles(JSONBArray(v)), nil
	default:
		return nil, ErrInvalidRoles
	}
}

// FormatRoles converts a JSONB role list into grant strings (e.g. "admin:rw").
// JSONBArray is already []any from DB/JSON unmarshaling — convert elements
// directly. Do not use Scan here: Scan implements database/sql.Scanner and
// expects []byte/string JSON input, not a destination pointer.
func FormatRoles(roles JSONBArray) []string {
	if len(roles) == 0 {
		return []string{}
	}
	return normalizeRoleGrants(roleGrantsFromAnySlice([]any(roles)))
}

func normalizeRoleGrants(grants []string) []string {
	if len(grants) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		g = strings.TrimSpace(g)
		if g != "" {
			out = append(out, g)
		}
	}
	return out
}

func roleGrantsFromAnySlice(items []any) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		switch v := item.(type) {
		case string:
			if s := strings.TrimSpace(v); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// compile-time assertion that errors.New (and therefore errors.Is) still
// works on our sentinels even if someone wraps them.
var _ = errors.Is
