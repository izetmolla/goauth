// Package todoist provides a Todoist sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/todoist"
//
//	todoist.New(todoist.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package todoist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/internal/common"
)

const ID = "todoist"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"data:read"}

// Overridable in tests.
var (
	syncAPIURL = "https://api.todoist.com/sync/v9/sync"
	httpClient = http.DefaultClient
)

// Options configures the Todoist provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Todoist provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = DefaultScopes
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "Todoist",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://todoist.com/oauth/authorize",
		TokenURL:            "https://todoist.com/oauth/access_token",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		AuthorizationStyle:  "body",
		Profile:             profile,
		FetchUserInfo:       fetchUserInfo,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
	return &goauth.OAuthUser{
		ID:       common.String(p["id"]),
		Name:     common.String(p["full_name"]),
		Email:    common.String(p["email"]),
		Image:    common.String(p["avatar_big"]),
		Provider: ID,
	}, nil
}

func fetchUserInfo(ctx context.Context, tokens goauth.TokenSet) (goauth.Profile, error) {
	body := strings.NewReader(`{"sync_token":"*","resource_types":["user"]}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, syncAPIURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("todoist userinfo: status %d: %s", resp.StatusCode, b)
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	user := common.Map(raw["user"])
	if user == nil {
		return goauth.Profile(raw), nil
	}
	return goauth.Profile(user), nil
}
