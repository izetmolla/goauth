package goauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// origin resolves the external base URL and whether it is HTTPS, honoring
// Config.AuthURL and request headers when AuthURL is unset.
func (a *Authorization) origin(r *http.Request) (string, bool, error) {
	if a == nil {
		return "", false, fmt.Errorf("authorization is not initialized")
	}
	if a.AuthURL != "" {
		return parseOriginURL(a.AuthURL)
	}
	// if !a.TrustHost {
	// 	return "", false, fmt.Errorf("untrusted host: %s", a.AuthURL)
	// }
	scheme := "http"
	isSecure := isSecureRequest(r)
	if isSecure {
		scheme = "https"
	}
	host := r.Host
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		host = fwd
	}

	return scheme + "://" + host, isSecure, nil
}

// parseOriginURL normalizes AuthURL into an absolute base URL. Values without a
// scheme default to https:// so OAuth redirect_uri values stay valid.
func parseOriginURL(raw string) (string, bool, error) {
	raw = strings.TrimSpace(strings.TrimRight(raw, "/"))
	if raw == "" {
		return "", false, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false, fmt.Errorf("invalid AuthURL: %w", err)
	}
	if u.Host == "" {
		return "", false, fmt.Errorf("invalid AuthURL: %q", raw)
	}
	return u.Scheme + "://" + u.Host, u.Scheme == "https", nil
}

// callbackQuery returns OAuth callback parameters from the query string, merging
// POST form fields when a provider uses response_mode=form_post (e.g. Sign in with Apple).
func callbackQuery(r *http.Request) map[string]string {
	q := r.URL.Query()
	merged := make(map[string]string, len(q)+4)
	for k, vs := range q {
		if len(vs) > 0 {
			merged[k] = vs[0]
		}
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		for k, vs := range r.PostForm {
			if len(vs) > 0 && vs[0] != "" && merged[k] == "" {
				merged[k] = vs[0]
			}
		}
	}
	return merged
}

// discover fills in any missing OAuth endpoints from the provider's OIDC issuer.
// It is a no-op when the endpoints are already set or no Issuer is configured.
func discover(ctx context.Context, p *OAuthProvider) error {
	if p == nil {
		return fmt.Errorf("oauth provider is required")
	}
	if p.Issuer == "" {
		return nil
	}
	if p.AuthorizationURL != "" && p.TokenURL != "" {
		return nil
	}
	wellKnown := strings.TrimRight(p.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc discovery: unexpected status %d", resp.StatusCode)
	}
	var cfg oidcConfig
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&cfg); err != nil {
		return fmt.Errorf("oidc discovery: decode: %w", err)
	}
	if p.AuthorizationURL == "" {
		p.AuthorizationURL = cfg.AuthorizationEndpoint
	}
	if p.TokenURL == "" {
		p.TokenURL = cfg.TokenEndpoint
	}
	if p.UserInfoURL == "" {
		p.UserInfoURL = cfg.UserinfoEndpoint
	}
	return nil
}

// callbackURL builds the provider callback URL for the current request.
func (a *Authorization) callbackURL(origin, providerID string) string {
	// TODO: Implement this
	basePath := "/api/authorization/provider/"
	return origin + basePath + providerID + "/callback"
}

func (a *Authorization) signInURL(origin, providerID string) string {
	basePath := "/api/authorization/provider/"
	return origin + basePath + providerID
}
