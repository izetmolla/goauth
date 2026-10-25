package goauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Providers are shared across requests, so concurrent OIDC discovery must
// not race on the provider's endpoint fields (run with -race).
func TestDiscoverConcurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(oidcConfig{
			AuthorizationEndpoint: "https://idp.test/authorize",
			TokenEndpoint:         "https://idp.test/token",
			UserinfoEndpoint:      "https://idp.test/userinfo",
		})
	}))
	defer srv.Close()

	p := &OAuthProvider{ProviderID: "test", Issuer: srv.URL}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := discover(context.Background(), p); err != nil {
				t.Errorf("discover: %v", err)
			}
		})
	}
	wg.Wait()

	if p.AuthorizationURL != "https://idp.test/authorize" || p.TokenURL != "https://idp.test/token" {
		t.Errorf("endpoints not discovered: %+v", p)
	}
}

func TestParseTokenResponseFormEncoded(t *testing.T) {
	ts, err := parseTokenResponse([]byte("access_token=abc&token_type=bearer&expires_in=3600"), "application/x-www-form-urlencoded")
	if err != nil {
		t.Fatalf("parseTokenResponse: %v", err)
	}
	if ts.AccessToken != "abc" || ts.ExpiresIn != 3600 {
		t.Errorf("got AccessToken=%q ExpiresIn=%d, want abc/3600", ts.AccessToken, ts.ExpiresIn)
	}
}
