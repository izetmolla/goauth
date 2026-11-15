package goauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newIssuer(t *testing.T, delay time.Duration, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		time.Sleep(delay)
		_ = json.NewEncoder(w).Encode(oidcConfig{
			AuthorizationEndpoint: srv.URL + "/authorize",
			TokenEndpoint:         srv.URL + "/token",
			UserinfoEndpoint:      srv.URL + "/userinfo",
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDiscoverRunsOnceUnderConcurrency(t *testing.T) {
	var hits atomic.Int32
	srv := newIssuer(t, 20*time.Millisecond, &hits)
	p := &OAuthProvider{ProviderID: "x", Issuer: srv.URL}

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if err := discover(context.Background(), p); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()

	if got := hits.Load(); got != 1 {
		t.Fatalf("issuer fetched %d times, want 1", got)
	}
	if p.AuthorizationURL != srv.URL+"/authorize" || p.TokenURL != srv.URL+"/token" {
		t.Fatalf("endpoints not filled: %+v", p)
	}
}

func TestDiscoverDoesNotBlockOtherProviders(t *testing.T) {
	var slowHits, fastHits atomic.Int32
	slow := &OAuthProvider{ProviderID: "slow", Issuer: newIssuer(t, 500*time.Millisecond, &slowHits).URL}
	fast := &OAuthProvider{ProviderID: "fast", Issuer: newIssuer(t, 0, &fastHits).URL}

	go func() { _ = discover(context.Background(), slow) }()
	for slowHits.Load() == 0 { // wait until the slow discovery is in flight
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	if err := discover(context.Background(), fast); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("fast provider waited %v behind the slow one", elapsed)
	}
}
