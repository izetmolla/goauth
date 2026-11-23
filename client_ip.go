package goauth

import (
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
)

// parseTrustedProxies parses Config.TrustedProxies (IPs or CIDRs). When
// trustCloudflare is true, Cloudflare's published edge ranges are appended.
func parseTrustedProxies(raw []string, trustCloudflare bool) ([]*net.IPNet, error) {
	if trustCloudflare {
		raw = append(append([]string(nil), raw...), CloudflareTrustedProxies...)
	}
	nets := make([]*net.IPNet, 0, len(raw))
	seen := map[string]struct{}{}
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		n, err := parseIPNet(s)
		if err != nil {
			return nil, fmt.Errorf("TrustedProxies entry %q: %w", s, err)
		}
		key := n.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		nets = append(nets, n)
	}
	return nets, nil
}

// trustedClientIP returns the client address for security decisions (IP
// access rules, login lockouts) and session metadata. Forwarded headers are
// honored only when the direct peer is a configured trusted proxy; otherwise
// anyone could pick their own address by sending the header.
//
// Header preference when the peer is trusted:
//  1. CF-Connecting-IP (Cloudflare; single client address, not spoofable by
//     the visitor when the request reached you from a Cloudflare edge)
//  2. True-Client-IP (some enterprise Cloudflare / CDN setups)
//  3. X-Forwarded-For (right to left, skipping trusted proxies)
//  4. X-Real-IP
func (a *Authorization) trustedClientIP(r *http.Request) string {
	peer := requestPeerIP(r)
	if !a.isTrustedProxy(peer) {
		return peer
	}
	if ip := singleForwardedIP(r.Header.Get("CF-Connecting-IP")); ip != "" {
		return ip
	}
	if ip := singleForwardedIP(r.Header.Get("True-Client-IP")); ip != "" {
		return ip
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
	if ip := singleForwardedIP(r.Header.Get("X-Real-Ip")); ip != "" {
		return ip
	}
	return peer
}

// singleForwardedIP returns the first comma-separated hop when it looks like
// an IP address; otherwise "".
func singleForwardedIP(raw string) string {
	ip, _, _ := strings.Cut(strings.TrimSpace(raw), ",")
	ip = strings.TrimSpace(ip)
	if ip == "" || net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

func requestPeerIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	return peer
}

// isTrustedProxy reports whether ip is in Config.TrustedProxies (and
// Cloudflare ranges when TrustCloudflare is set).
func (a *Authorization) isTrustedProxy(ip string) bool {
	if a == nil || len(a.trustedProxies) == 0 {
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

// peerIsTrustedProxy reports whether the request's TCP peer is a configured
// trusted proxy (used before honoring X-Forwarded-* headers).
func (a *Authorization) peerIsTrustedProxy(r *http.Request) bool {
	if a == nil || r == nil {
		return false
	}
	return a.isTrustedProxy(requestPeerIP(r))
}
