package goauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxResponseBytes caps how much of a provider's HTTP response we read, so a
// misbehaving or compromised endpoint cannot exhaust memory.
const maxResponseBytes = 1 << 20 // 1 MiB

// oidcConfig is the subset of an OpenID Connect discovery document we consume.
type oidcConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// authorizationURL builds the full authorization redirect URL including scope,
// state, and PKCE challenge as applicable.
func authorizationURL(p *OAuthProvider, callbackURL, state, codeVerifier, nonce string) string {
	if p == nil || p.AuthorizationURL == "" {
		return ""
	}
	params := url.Values{}
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", callbackURL)
	if len(p.Scopes) > 0 {
		params.Set("scope", strings.Join(p.Scopes, " "))
	}
	if providerUsesCheck(p, CheckState) && state != "" {
		params.Set("state", state)
	}
	if providerUsesCheck(p, CheckPKCE) && codeVerifier != "" {
		params.Set("code_challenge", pkceChallenge(codeVerifier))
		params.Set("code_challenge_method", "S256")
	}
	if providerUsesCheck(p, CheckNonce) && nonce != "" {
		params.Set("nonce", nonce)
	}
	for k, vs := range p.AuthorizationParams {
		for _, v := range vs {
			params.Set(k, v)
		}
	}
	sep := "?"
	if strings.Contains(p.AuthorizationURL, "?") {
		sep = "&"
	}
	return p.AuthorizationURL + sep + params.Encode()
}

// exchangeCode swaps an authorization code for tokens at the token endpoint.
func exchangeCode(ctx context.Context, p *OAuthProvider, code, callbackURL, codeVerifier string) (*TokenSet, error) {
	if p == nil {
		return nil, fmt.Errorf("oauth provider is required")
	}
	if code == "" {
		return nil, fmt.Errorf("authorization code is required")
	}
	if p.TokenURL == "" {
		return nil, fmt.Errorf("provider missing TokenURL")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", callbackURL)
	if providerUsesCheck(p, CheckPKCE) && codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	useHeader := p.AuthorizationStyle == "header"
	if !useHeader {
		form.Set("client_id", p.ClientID)
		form.Set("client_secret", p.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if useHeader {
		basic := base64.StdEncoding.EncodeToString([]byte(p.ClientID + ":" + p.ClientSecret))
		req.Header.Set("Authorization", "Basic "+basic)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token exchange: status %d: %s", resp.StatusCode, string(body))
	}

	tokens, err := parseTokenResponse(body, resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

// parseTokenResponse handles both JSON and (legacy) form-encoded token bodies,
// preserving every field in TokenSet.Raw.
func parseTokenResponse(body []byte, contentType string) (*TokenSet, error) {
	raw := map[string]any{}
	if strings.Contains(contentType, "application/json") || (len(body) > 0 && body[0] == '{') {
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("token exchange: decode json: %w", err)
		}
	} else {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, fmt.Errorf("token exchange: decode form: %w", err)
		}
		for k := range values {
			raw[k] = values.Get(k)
		}
	}

	ts := &TokenSet{Raw: raw}
	ts.AccessToken = asString(raw["access_token"])
	ts.TokenType = asString(raw["token_type"])
	ts.IDToken = asString(raw["id_token"])
	ts.RefreshToken = asString(raw["refresh_token"])
	ts.Scope = asString(raw["scope"])
	if v, ok := raw["expires_in"].(float64); ok {
		ts.ExpiresIn = int64(v)
	}
	return ts, nil
}

// fetchUserInfo calls the userinfo endpoint with the access token.
func fetchUserInfo(ctx context.Context, p *OAuthProvider, tokens *TokenSet) (Profile, error) {
	if p == nil {
		return nil, fmt.Errorf("oauth provider is required")
	}
	if tokens == nil {
		return nil, fmt.Errorf("tokens are required")
	}
	if p.UserInfoURL == "" {
		// OIDC providers without a userinfo endpoint rely on the id_token; the
		// provider's Profile function can parse it from tokens.
		return Profile{}, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		return nil, fmt.Errorf("userinfo: status %d: %s", resp.StatusCode, string(body))
	}
	var profile Profile
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&profile); err != nil {
		return nil, fmt.Errorf("userinfo: decode: %w", err)
	}
	return profile, nil
}
