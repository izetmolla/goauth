package goauth

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// OriginAllowlist is a parsed list of exact origins and subdomain wildcards
// (scheme://*.example.com). Used by TrustedRedirectOrigins and passkey RPOrigins.
type OriginAllowlist struct {
	Exact     []string
	Wildcards []string
}

// All returns Exact and Wildcards concatenated (Exact first).
func (a OriginAllowlist) All() []string {
	out := make([]string, 0, len(a.Exact)+len(a.Wildcards))
	out = append(out, a.Exact...)
	out = append(out, a.Wildcards...)
	return out
}

// ParseOriginAllowlist normalizes and validates origin entries.
//
// Accepted forms:
//   - exact: https://app.example.com, http://localhost:3001, example.com
//   - wildcard: https://*.example.com, *.example.com (nested subdomains;
//     apex example.com is NOT matched — list it separately)
//
// Rejects malformed wildcards (*., foo.*.bar, etc.) so config fails fast.
func ParseOriginAllowlist(raw []string) (OriginAllowlist, error) {
	var out OriginAllowlist
	seen := map[string]struct{}{}
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		origin, _, err := parseOriginURL(s)
		if err != nil {
			return OriginAllowlist{}, fmt.Errorf("origin %q: %w", s, err)
		}
		if origin == "" {
			continue
		}
		if err := validateTrustedOriginPattern(origin); err != nil {
			return OriginAllowlist{}, fmt.Errorf("origin %q: %w", s, err)
		}
		key := strings.ToLower(origin)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if isWildcardOrigin(origin) {
			out.Wildcards = append(out.Wildcards, origin)
		} else {
			out.Exact = append(out.Exact, origin)
		}
	}
	return out, nil
}

// NormalizeRPID validates a WebAuthn relying-party ID (hostname only).
// Wildcards and URL schemes are rejected — use e.g. "example.com", not
// "*.example.com" or "https://example.com".
func NormalizeRPID(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("RPID is empty")
	}
	if strings.Contains(raw, "*") {
		return "", fmt.Errorf("RPID %q must be a concrete domain (e.g. example.com), not a wildcard", raw)
	}
	if strings.Contains(raw, "://") {
		origin, _, err := parseOriginURL(raw)
		if err != nil {
			return "", fmt.Errorf("RPID %q: %w", raw, err)
		}
		_, host, ok := splitOrigin(origin)
		if !ok {
			return "", fmt.Errorf("RPID %q: invalid URL", raw)
		}
		hostname, port, err := splitHostPort(host)
		if err != nil {
			return "", fmt.Errorf("RPID %q: %w", raw, err)
		}
		if port != "" {
			return "", fmt.Errorf("RPID %q must not include a port", raw)
		}
		raw = hostname
	}
	raw = strings.TrimPrefix(raw, ".")
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" || strings.ContainsAny(raw, "/ \\?#") {
		return "", fmt.Errorf("RPID %q is not a valid domain", raw)
	}
	return raw, nil
}

func isWildcardOrigin(origin string) bool {
	_, host, ok := splitOrigin(origin)
	if !ok {
		return false
	}
	hostname, _, err := splitHostPort(host)
	if err != nil {
		return false
	}
	return strings.HasPrefix(strings.ToLower(hostname), "*.")
}

// validateTrustedOriginPattern rejects malformed wildcard hosts
// (e.g. "*", "*.", "foo.*.bar").
func validateTrustedOriginPattern(origin string) error {
	_, host, ok := splitOrigin(origin)
	if !ok {
		return errors.New("invalid origin")
	}
	hostname, _, err := splitHostPort(host)
	if err != nil {
		return err
	}
	if !strings.Contains(hostname, "*") {
		return nil
	}
	if !strings.HasPrefix(hostname, "*.") {
		return errors.New("wildcard host must be of the form *.example.com")
	}
	suffix := hostname[2:]
	if suffix == "" || strings.Contains(suffix, "*") || strings.HasPrefix(suffix, ".") || strings.HasSuffix(suffix, ".") {
		return fmt.Errorf("invalid wildcard domain %q", hostname)
	}
	return nil
}

func splitOrigin(origin string) (scheme, host string, ok bool) {
	origin = strings.TrimSpace(origin)
	i := strings.Index(origin, "://")
	if i <= 0 {
		return "", "", false
	}
	scheme = origin[:i]
	host = origin[i+3:]
	if scheme == "" || host == "" {
		return "", "", false
	}
	return scheme, host, true
}

// splitHostPort splits "host" or "host:port". Wildcard hosts like
// "*.example.com:3001" are supported.
func splitHostPort(hostport string) (host, port string, err error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", "", errors.New("empty host")
	}
	if strings.HasPrefix(hostport, "[") {
		h, p, e := net.SplitHostPort(hostport)
		return h, p, e
	}
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		suffix := hostport[i+1:]
		if suffix != "" && isAllDigits(suffix) {
			return hostport[:i], suffix, nil
		}
	}
	return hostport, "", nil
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// OriginMatches reports whether candidate (scheme://host) is allowed by a
// trusted origin entry (exact match or *.domain wildcard).
func OriginMatches(candidate, trusted string) bool {
	return originMatchesTrusted(candidate, trusted)
}

// originMatchesTrusted reports whether candidate (scheme://host) is allowed by
// a trusted origin entry (exact or *.domain wildcard).
func originMatchesTrusted(candidate, trusted string) bool {
	if strings.EqualFold(candidate, trusted) {
		return true
	}
	cScheme, cHost, ok1 := splitOrigin(candidate)
	tScheme, tHost, ok2 := splitOrigin(trusted)
	if !ok1 || !ok2 || !strings.EqualFold(cScheme, tScheme) {
		return false
	}
	cName, cPort, err1 := splitHostPort(cHost)
	tName, tPort, err2 := splitHostPort(tHost)
	if err1 != nil || err2 != nil {
		return false
	}
	if !strings.EqualFold(cPort, tPort) {
		return false
	}
	if !strings.HasPrefix(strings.ToLower(tName), "*.") {
		return false
	}
	base := strings.ToLower(tName[2:])
	cName = strings.ToLower(cName)
	if cName == "" || base == "" || cName == base {
		return false
	}
	return strings.HasSuffix(cName, "."+base)
}
