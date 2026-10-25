---
title: Reusable package
description: Package a custom provider as New(Options) with defaults and an overridable Profile, like the built-in providers.
---

# Packaging a provider for reuse

Once a provider works, move it into its own package. Every app (and every developer) then configures it in one line, exactly like the built-in ones:

```go
Providers: []goauth.Provider{
	google.New(googleID, googleSecret),
	acme.New(acme.Options{ClientID: id, ClientSecret: secret}),
},
```

## Layout

```text
myapp/
└── providers/
    └── acme/
        ├── acme.go        # Options, New, DefaultProfile
        ├── acme_test.go   # see "Testing"
        └── README.md      # setup steps at the provider
```

## The package

The shape follows `providers/azuread`: an `Options` struct, a `New` constructor that fills in defaults, and an exported `DefaultProfile` that callers can wrap or replace.

```go title="providers/acme/acme.go"
// Package acme provides an "Acme ID" sign-in provider for goauth.
//
//	import "example.com/myapp/providers/acme"
//
//	acme.New(acme.Options{
//		ClientID:     os.Getenv("ACME_CLIENT_ID"),
//		ClientSecret: os.Getenv("ACME_CLIENT_SECRET"),
//	})
package acme

import (
	"errors"
	"net/url"

	"github.com/izetmolla/goauth"
)

// ID is the provider id used in goauth routes:
// /api/authorization/provider/acme and .../acme/callback.
const ID = "acme"

// DefaultBaseURL is Acme's production identity server.
const DefaultBaseURL = "https://id.acme.example"

// DefaultScopes are requested when Options.Scopes is nil.
var DefaultScopes = []string{"openid", "email", "profile"}

// Options configures the Acme provider.
type Options struct {
	ClientID     string // required
	ClientSecret string // required

	// BaseURL overrides the identity server, e.g. for a staging tenant or tests.
	BaseURL string
	// Scopes replace DefaultScopes.
	Scopes []string
	// AuthorizationParams are appended to the authorize request.
	AuthorizationParams url.Values
	// Profile replaces DefaultProfile.
	Profile func(goauth.Profile, goauth.TokenSet) (*goauth.OAuthUser, error)
}

// New returns a configured Acme provider.
func New(o Options) goauth.Provider {
	base := o.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
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
		DisplayName:         "Acme ID",
		Kind:                goauth.ProviderOAuth,
		ClientID:            o.ClientID,
		ClientSecret:        o.ClientSecret,
		AuthorizationURL:    base + "/oauth/authorize",
		TokenURL:            base + "/oauth/token",
		UserInfoURL:         base + "/api/me",
		AuthorizationParams: o.AuthorizationParams,
		Scopes:              scopes,
		Checks:              []goauth.Check{goauth.CheckPKCE, goauth.CheckState},
		Profile:             profile,
	}
}

// DefaultProfile maps Acme's /api/me response to a goauth.OAuthUser.
func DefaultProfile(p goauth.Profile, tokens goauth.TokenSet) (*goauth.OAuthUser, error) {
	id := str(p["user_id"])
	if id == "" {
		return nil, errors.New("acme: profile has no user_id")
	}
	return &goauth.OAuthUser{
		ID:          id,
		Email:       str(p["email"]),
		Name:        str(p["full_name"]),
		AvatarURL:   str(p["avatar"]),
		AccessToken: tokens.AccessToken,
		RawData:     p,
	}, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
```

## Design guidelines

- **Return `goauth.Provider`** from `New`, so the concrete type can change later. Callers who need to tweak fields can still assert `.(*goauth.OAuthProvider)`.
- **Export the id as a constant** (`acme.ID`) so apps can compare `profile["provider"] == acme.ID` instead of repeating strings.
- **Make the base URL configurable.** It lets users point at a staging or self-hosted tenant, and it lets you test against a fake server.
- **Export `DefaultScopes` and `DefaultProfile`**, and let `Options` override both. Users can then extend the defaults instead of copying them:

  ```go
  acme.New(acme.Options{
  	ClientID:     id,
  	ClientSecret: secret,
  	Scopes:       append(slices.Clone(acme.DefaultScopes), "groups"),
  	Profile: func(p goauth.Profile, t goauth.TokenSet) (*goauth.OAuthUser, error) {
  		u, err := acme.DefaultProfile(p, t)
  		if err == nil {
  			u.Location, _ = p["office"].(string)
  		}
  		return u, err
  	},
  })
  ```

- **Enable every check the provider supports.** Users should get secure defaults without thinking about them.
- **Document the redirect URI** in the package comment or README: `{AuthURL}/api/authorization/provider/acme/callback`.

## Contributing a provider to goauth

To add a provider to goauth itself, open a pull request on [GitHub](https://github.com/izetmolla/goauth) with:

1. `providers/<name>/<name>.go` following the package above. Inside goauth, use `common.String(v)` from `providers/internal/common` instead of a local `str` helper.
2. `providers/<name>/README.md` with the provider console setup and an options table (see `providers/azuread/README.md`).
3. A test using a fake server, as shown in [Testing](./testing.md).
4. A row in `providers/README.md`.

Run the linters and tests before submitting:

```bash
go vet ./... && go test -race ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...
```
