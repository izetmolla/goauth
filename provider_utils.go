package goauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// origin resolves the external base URL and whether it is HTTPS, honoring
// Config.AuthURL and request headers when AuthURL is unset.
func (a *Authorization) origin(c fiber.Ctx) (string, bool, error) {
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
	isSecure := c.Protocol() == "https"
	if isSecure {
		scheme = "https"
	}
	host := c.Host()
	if fwd := c.Get("X-Forwarded-Host"); fwd != "" {
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
func callbackQuery(c fiber.Ctx) map[string]string {
	q := c.Queries()
	merged := make(map[string]string, len(q)+4)
	for k, v := range q {
		merged[k] = v
	}
	if c.Method() == fiber.MethodPost {
		for key, value := range c.RequestCtx().PostArgs().All() {
			k := string(key)
			if v := string(value); v != "" && merged[k] == "" {
				merged[k] = v
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
