// Package vk provides a VK sign-in provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/vk"
//
//	vk.New(vk.Options{
//		ClientID:     "YOUR_CLIENT_ID",
//		ClientSecret: "YOUR_CLIENT_SECRET",
//	})
package vk

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/internal/common"
)

// ID is the provider id used in goauth routes: {base}/provider/vk.
const ID = "vk"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"email"}

// Overridable in tests.
var (
	usersAPIURL = "https://api.vk.com/method/users.get"
	httpClient  = common.HTTPClient
)

// Options configures the VK provider.
type Options struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	AuthorizationParams url.Values
	Profile             func(profile goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured VK provider.
func New(o Options) goauth.Provider {
	scopes := o.Scopes
	if scopes == nil {
		scopes = DefaultScopes
	}
	profile := o.Profile
	if profile == nil {
		profile = DefaultProfile
	}
	authParams := o.AuthorizationParams
	if authParams == nil {
		authParams = url.Values{"v": {"5.131"}}
	} else {
		if _, ok := authParams["v"]; !ok {
			authParams.Set("v", "5.131")
		}
	}
	return &goauth.OAuthProvider{
		ProviderID:          ID,
		DisplayName:         "VK",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    "https://oauth.vk.com/authorize",
		TokenURL:            "https://oauth.vk.com/access_token",
		AuthorizationParams: authParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckState},
		AuthorizationStyle:  "body",
		Profile:             profile,
		FetchUserInfo:       fetchUserInfo,
	}
}

// DefaultProfile maps the provider profile to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error) {
	resp, _ := p["response"].([]any)
	user := p
	if len(resp) > 0 {
		if m := common.Map(resp[0]); m != nil {
			user = m
		}
	}
	email := common.String(p["email"])
	if email == "" {
		email = common.RawString(tokens.Raw, "email")
	}
	return &goauth.OAuthUser{
		ID:        common.String(user["id"]),
		Name:      strings.TrimSpace(common.String(user["first_name"]) + " " + common.String(user["last_name"])),
		FirstName: common.String(user["first_name"]),
		LastName:  common.String(user["last_name"]),
		Email:     email,
		Image:     common.String(user["photo_100"]),
		Provider:  ID,
	}, nil
}

func fetchUserInfo(ctx context.Context, tokens goauth.TokenSet) (goauth.Profile, error) {
	query := url.Values{"fields": {"photo_100"}, "v": {"5.131"}, "access_token": {tokens.AccessToken}}
	if userID := common.RawString(tokens.Raw, "user_id"); userID != "" {
		query.Set("user_ids", userID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, usersAPIURL+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vk userinfo: %w", err)
	}
	defer resp.Body.Close()
	profile := goauth.Profile{}
	if err := common.DecodeJSON(resp, "vk userinfo", &profile); err != nil {
		return nil, err
	}
	if profile == nil { // a body of JSON null
		profile = goauth.Profile{}
	}
	if email := common.RawString(tokens.Raw, "email"); email != "" {
		profile["email"] = email
	}
	return profile, nil
}
