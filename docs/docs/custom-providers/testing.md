---
title: Testing
description: Test a custom provider's complete sign-in flow against a fake OAuth server with net/http/httptest.
---

# Testing a custom provider

You can test the **whole** sign-in flow (start, provider redirect, callback, code exchange, userinfo, `ResolveUser`, session creation) in a normal `go test`, without a browser, real credentials or network access.

The idea:

1. Start a **fake provider** with `httptest`: a token endpoint and a userinfo endpoint.
2. Point the provider's `BaseURL` at it. (This is why the [reusable package](./reusable-package.md) makes the base URL configurable.)
3. Start your app with `httptest` and drive it with an `http.Client` that keeps cookies, just like a browser.

The authorize step needs no fake: the test reads the authorization URL as JSON (`?json=true`), takes its `state`, and calls the callback directly as if the provider had redirected back.

## The test

The test needs an in-memory SQLite database:

```bash
go get github.com/glebarez/sqlite
```

```go title="providers/acme/acme_test.go"
package acme_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"example.com/myapp/providers/acme"

	"github.com/glebarez/sqlite"
	"github.com/izetmolla/goauth"
	"gorm.io/gorm"
)

// fakeAcme is a minimal OAuth server: it accepts any code that the
// authorize step handed out and returns a fixed user.
func fakeAcme(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code") != "good-code" || r.FormValue("code_verifier") == "" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "acme-access", "token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("GET /api/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer acme-access" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id": "acme-42", "email": "jane@acme.example", "full_name": "Jane Doe",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestSignInWithAcme(t *testing.T) {
	idp := fakeAcme(t)

	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE users (id TEXT PRIMARY KEY, roles TEXT DEFAULT '[]')`)
	db.Exec(`CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id TEXT, type TEXT, ip_address TEXT,
		user_agent TEXT, method TEXT, account TEXT, expires_at DATETIME, is_deleted NUMERIC DEFAULT 0,
		created_at DATETIME, updated_at DATETIME, deleted_at DATETIME)`)
	db.Exec(`INSERT INTO users (id, roles) VALUES ('u-1', '["user:r"]')`)

	var gotProfile goauth.Profile
	app := httptest.NewUnstartedServer(nil)
	auth, err := goauth.New(&goauth.Config{
		JWTSecret: "test-secret",
		AuthURL:   "http://" + app.Listener.Addr().String(),
		DB:        db,
		Providers: []goauth.Provider{acme.New(acme.Options{
			ClientID: "client", ClientSecret: "secret", BaseURL: idp.URL,
		})},
		ResolveUser: func(_ context.Context, p goauth.Profile) (*goauth.User, bool, error) {
			gotProfile = p
			return &goauth.User{ID: "u-1"}, false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	app.Config.Handler = auth.Handler()
	app.Start()
	defer app.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// 1. Start sign-in and read the authorization URL as JSON.
	res, err := client.Get(app.URL + "/api/authorization/provider/acme?json=true")
	if err != nil {
		t.Fatal(err)
	}
	var start struct{ URL string }
	_ = json.NewDecoder(res.Body).Decode(&start)
	res.Body.Close()
	authURL, _ := url.Parse(start.URL)
	q := authURL.Query()
	if !strings.HasPrefix(start.URL, idp.URL+"/oauth/authorize") || q.Get("code_challenge") == "" {
		t.Fatalf("unexpected authorization URL: %s", start.URL)
	}

	// 2. Pretend the user approved: the provider redirects back with code + state.
	res, err = client.Get(q.Get("redirect_uri") + "?code=good-code&state=" + url.QueryEscape(q.Get("state")))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(body), `"type":"sign_in"`) {
		t.Fatalf("callback did not sign in:\n%s", body)
	}

	// 3. ResolveUser saw the raw profile, and a session row exists.
	if gotProfile["email"] != "jane@acme.example" || gotProfile["provider"] != "acme" {
		t.Fatalf("unexpected profile: %v", gotProfile)
	}
	var sessions int64
	db.Table("sessions").Where("user_id = ? AND method = ?", "u-1", "acme").Count(&sessions)
	if sessions != 1 {
		t.Fatalf("want 1 session, got %d", sessions)
	}
}

func TestDefaultProfileRequiresUserID(t *testing.T) {
	if _, err := acme.DefaultProfile(goauth.Profile{"email": "x@y"}, goauth.TokenSet{}); err == nil {
		t.Fatal("expected an error for a profile without user_id")
	}
}
```

```bash
go test ./providers/acme -v
```

```text
=== RUN   TestSignInWithAcme
--- PASS: TestSignInWithAcme (0.01s)
=== RUN   TestDefaultProfileRequiresUserID
--- PASS: TestDefaultProfileRequiresUserID (0.00s)
PASS
```

## What the test proves

| Assertion | Proves |
|---|---|
| Authorization URL starts with the fake server and has `code_challenge` | Endpoints and PKCE are configured |
| The fake token endpoint rejects requests without `code_verifier` | goauth sends the PKCE verifier and the right code |
| The fake userinfo endpoint requires `Bearer acme-access` | The access token from the exchange is used |
| Callback page contains `"type":"sign_in"` | State check, exchange, `Profile` and `ResolveUser` all succeeded |
| `ResolveUser` saw `email` and `provider: "acme"` | Your profile keys match what the provider returns |
| One session row with `method = 'acme'` | A real goauth session was created |

## More cases worth testing

Add table-driven cases by changing the fake server's responses:

- **Token endpoint returns 400** → the callback page shows "Token exchange failed".
- **Userinfo omits the id** → your `Profile` returns an error and no session is created.
- **Wrong `state`** → call the callback with `state=bogus` and expect "State mismatch".
- **Form-encoded token response** (`access_token=...&expires_in=3600`, as some older providers return) → still signs in.
- **`AuthorizationStyle: "header"`** → assert the fake token endpoint receives `r.BasicAuth()`.

## Testing your `ResolveUser`

`ResolveUser` is an ordinary function, so unit-test it directly with hand-written profiles:

```go
func TestResolveUserCreatesAccount(t *testing.T) {
	db := newTestDB(t)
	u, isNew, err := resolveUser(db)(t.Context(), goauth.Profile{
		"provider": "acme", "user_id": "acme-42", "email": "jane@acme.example",
	})
	if err != nil || !isNew || u.ID == "" {
		t.Fatalf("got %+v, %v, %v", u, isNew, err)
	}
}
```
