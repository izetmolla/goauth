package goauth

import (
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
)

// parseTrustedProxies parses Config.TrustedProxies (IPs or CIDRs).
func parseTrustedProxies(raw []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(raw))
	for _, s := range raw {
		n, err := parseIPNet(s)
		if err != nil {
			return nil, fmt.Errorf("TrustedProxies entry %q: %w", s, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// trustedClientIP returns the client address for security decisions (IP
// access rules, login lockouts). X-Forwarded-For and X-Real-IP are honored
// only when the direct peer is a configured trusted proxy; otherwise anyone
// could pick their own address by sending the header. X-Forwarded-For is read
// right to left, skipping trusted proxies, so a client cannot prepend a fake
// address either.
func (a *Authorization) trustedClientIP(r *http.Request) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	if !a.isTrustedProxy(peer) {
		return peer
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		hops := strings.Split(fwd, ",")
		for i, hop := range slices.Backward(hops) {
			hop := strings.TrimSpace(hop)
			if hop == "" {
				continue
			}
			if i == 0 || !a.isTrustedProxy(hop) {
				return hop
			}
		}
	}
	if ip := strings.TrimSpace(r.Header.Get("X-Real-Ip")); ip != "" {
		return ip
	}
	return peer
}

// isTrustedProxy reports whether ip is in Config.TrustedProxies.
func (a *Authorization) isTrustedProxy(ip string) bool {
	if len(a.trustedProxies) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range a.trustedProxies {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
