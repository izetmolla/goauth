package goauth

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

// The MFA challenge can carry the OAuth provider's tokens, so it must be
// unreadable by the browser, not just signed.
func TestMFAChallengeIsEncrypted(t *testing.T) {
	a := newMFAAuth(t, openMFADB(t), true)
	const secretToken = "provider-refresh-token-must-stay-private"
	token, err := a.issueMFAChallenge("user-1", "google", "/home", &Account{RefreshToken: secretToken})
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{secretToken, "user-1", "refresh_token"} {
		if strings.Contains(token, leak) || strings.Contains(decodeBase64Loose(token), leak) {
			t.Fatalf("challenge token exposes %q", leak)
		}
	}
	ch, err := a.decodeMFAChallenge(token)
	if err != nil || ch.UserID != "user-1" || ch.Account == nil || ch.Account.RefreshToken != secretToken {
		t.Fatalf("round trip: %+v, %v", ch, err)
	}
	tampered := token[:len(token)-2] + "AA"
	if _, err := a.decodeMFAChallenge(tampered); err == nil {
		t.Fatal("a tampered challenge decoded")
	}
}

// decodeBase64Loose decodes s as raw URL base64, or returns "".
func decodeBase64Loose(s string) string {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return string(b)
}

// RFC 6238 section 5.2: a TOTP code must be accepted only once.
func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	a := newMFAAuth(t, openMFADB(t), true)
	enrollTOTPUser(t, a, "user-1")
	row, err := a.loadTotpFactor(t.Context(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := a.totp.decryptSecret(row.SecretEnc)
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCodeCustom(string(secret), time.Now(), totp.ValidateOpts{
		Period: a.totp.period, Digits: otp.Digits(a.totp.digits), Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.checkTOTPCode(t.Context(), "user-1", code); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := a.checkTOTPCode(t.Context(), "user-1", code); !errors.Is(err, errMFAInvalid) {
		t.Fatalf("second use: err = %v, want errMFAInvalid", err)
	}
}

// Only the X-Auth-Flow header may skip CSRF: a cross-site form can add
// ?flow=token to the URL but cannot set a header.
func TestLoginAsQueryFlowNeedsCSRF(t *testing.T) {
	db := openLoginAsDB(t)
	seedLoginAsUsers(t, db)
	a := newLoginAsAuth(t, db, true)
	adminSID, err := a.CreateSession(NewAuthorizeOptions(a.WithUserID("admin-1"), a.WithMethod("credentials")))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultBasePath+"/login_as?flow=token", strings.NewReader(`{"user_id":"user-2"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: a.cookieSessionName, Value: adminSID})
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestLoginAsRefusesSameSiteGet(t *testing.T) {
	db := openLoginAsDB(t)
	seedLoginAsUsers(t, db)
	a := newLoginAsAuth(t, db, true)
	adminSID, err := a.CreateSession(NewAuthorizeOptions(a.WithUserID("admin-1"), a.WithMethod("credentials")))
	if err != nil {
		t.Fatal(err)
	}
	for site, want := range map[string]int{"same-site": http.StatusForbidden, "same-origin": http.StatusOK} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+"/login_as?user_id=user-2", nil)
		req.Header.Set("Sec-Fetch-Site", site)
		req.Header.Set("Accept", "application/json")
		req.AddCookie(&http.Cookie{Name: a.cookieSessionName, Value: adminSID})
		a.Handler().ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Sec-Fetch-Site %s: got %d, want %d (%s)", site, rec.Code, want, rec.Body.String())
		}
	}
}

func TestNewRejectsInvalidProvidersAndURLs(t *testing.T) {
	profile := func(Profile, TokenSet) (*OAuthUser, error) { return &OAuthUser{}, nil }
	cases := map[string]Config{
		"zero duration":     {AccessTokenDuration: "0s"},
		"overflow duration": {RefreshTokenDuration: "9999999999y"},
		"ftp AuthURL":       {AuthURL: "ftp://example.com"},
		"nil provider":      {Providers: []Provider{nil}},
		"empty id":          {Providers: []Provider{&CredentialsProvider{}}},
		"duplicate ids": {Providers: []Provider{
			&OAuthProvider{ProviderID: "x", Profile: profile},
			&OAuthProvider{ProviderID: "x", Profile: profile},
		}},
		"oauth without Profile": {Providers: []Provider{&OAuthProvider{ProviderID: "x"}}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			cfg.JWTSecret, cfg.DB = hardeningSecret, &gorm.DB{}
			if _, err := New(&cfg); err == nil {
				t.Fatal("New accepted an invalid config")
			}
		})
	}
}

func TestParseTokenResponseRejectsErrors(t *testing.T) {
	for name, body := range map[string]string{
		"error with status 200": `{"error":"bad_verification_code","error_description":"expired"}`,
		"no access token":       `{"token_type":"bearer"}`,
	} {
		if _, err := parseTokenResponse([]byte(body), "application/json"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckIDTokenNonce(t *testing.T) {
	idToken := func(nonce string) string {
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "1", "nonce": nonce}).SignedString([]byte("idp"))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if err := checkIDTokenNonce(idToken("n-1"), "n-1"); err != nil {
		t.Errorf("matching nonce: %v", err)
	}
	if err := checkIDTokenNonce(idToken("n-2"), "n-1"); err == nil {
		t.Error("mismatched nonce accepted")
	}
	if err := checkIDTokenNonce(idToken("n-1"), ""); err == nil {
		t.Error("missing nonce cookie accepted")
	}
	if err := checkIDTokenNonce("", "n-1"); err != nil {
		t.Errorf("no ID token: %v", err)
	}
}

// Regression: a Profile function returning (nil, nil) used to panic.
func TestOAuthCallbackProfileWithoutUser(t *testing.T) {
	idp := http.NewServeMux()
	idp.HandleFunc("POST /token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"at","token_type":"Bearer"}`)
	})
	idp.HandleFunc("GET /me", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"sub":"1"}`)
	})
	srv := httptest.NewServer(idp)
	defer srv.Close()

	a := newHardeningAuth(t, Config{
		Providers: []Provider{&OAuthProvider{
			ProviderID:       "fake",
			AuthorizationURL: srv.URL + "/authorize",
			TokenURL:         srv.URL + "/token",
			UserInfoURL:      srv.URL + "/me",
			Profile:          func(Profile, TokenSet) (*OAuthUser, error) { return nil, nil },
		}},
		ResolveUser: func(context.Context, Profile) (*User, bool, error) { return &User{ID: "u"}, false, nil },
	})
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		DefaultBasePath+"/provider/fake/callback?code=c", nil))
	if !strings.Contains(rec.Body.String(), "Profile mapping returned no user") {
		t.Fatalf("callback page: %s", rec.Body.String())
	}
}

func TestSignOutAndRevocation(t *testing.T) {
	db := openLoginAsDB(t)
	seedLoginAsUsers(t, db)
	a := newLoginAsAuth(t, db, false)
	ctx := t.Context()

	tokens, sid, err := a.Authorize(a.WithUserID("user-2"))
	if err != nil {
		t.Fatal(err)
	}
	// API client: sign out with the refresh token.
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, DefaultBasePath+"/signout", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.RefreshToken)
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("signout: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := a.GetSession(ctx, sid); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("after signout: %v", err)
	}

	// Browser: sign out with the cookie, which is also expired.
	_, sid2, _ := a.Authorize(a.WithUserID("user-2"))
	rec = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(ctx, http.MethodPost, DefaultBasePath+"/signout", nil)
	req.AddCookie(&http.Cookie{Name: a.cookieSessionName, Value: sid2})
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("cookie signout: %d %v", rec.Code, rec.Header())
	}
	if _, err := a.GetSession(ctx, sid2); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("after cookie signout: %v", err)
	}

	_, sid3, _ := a.Authorize(a.WithUserID("user-3"))
	_, sid4, _ := a.Authorize(a.WithUserID("user-3"))
	if err := a.RevokeUserSessions(ctx, "user-3"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{sid3, sid4} {
		if _, err := a.GetSession(ctx, id); !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("session %s after RevokeUserSessions: %v", id, err)
		}
	}
}

func TestWEBMiddlewareSharesThePrincipal(t *testing.T) {
	db := openLoginAsDB(t)
	seedLoginAsUsers(t, db)
	a := newLoginAsAuth(t, db, false)
	_, sid, err := a.Authorize(a.WithUserID("user-2"))
	if err != nil {
		t.Fatal(err)
	}
	var got AuthData
	page := a.UseWEBAuthorization()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// The session is gone, so only the middleware's copy can answer.
		db.Exec(`DELETE FROM sessions`)
		got, _ = a.GetAuthDataWEB(r, r.Context())
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/app?x=1", nil)
	req.AddCookie(&http.Cookie{Name: a.cookieSessionName, Value: sid})
	page.ServeHTTP(httptest.NewRecorder(), req)
	if got.UserID != "user-2" || got.SessionID != sid {
		t.Fatalf("GetAuthDataWEB = %+v", got)
	}

	rec := httptest.NewRecorder()
	page.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/app?x=1", nil))
	want := DefaultSignInRedirectURL + "?redirectUrl=" + url.QueryEscape("http://example.com/app?x=1")
	if rec.Code != http.StatusTemporaryRedirect || rec.Header().Get("Location") != want {
		t.Fatalf("anonymous: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestFormatUserKeepsIDAndRoles(t *testing.T) {
	got := FormatUser(&User{ID: "real", Roles: JSONBArray{"a"}, User: JSONBAny{"id": "spoofed", "name": "Jane"}}).(map[string]any)
	if got["id"] != "real" || got["name"] != "Jane" {
		t.Errorf("FormatUser = %v", got)
	}
}

func TestCheckPasswordRejectsUnboundedHash(t *testing.T) {
	for _, hash := range []string{
		"$pbkdf2-sha256$2000000000$c2FsdA$xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o",
		"$pbkdf2-sha256$4096$c2FsdA$AAAA",
	} {
		if CheckPassword(hash, "password") {
			t.Errorf("CheckPassword accepted %q", hash)
		}
	}
}

func TestAuthorizationParamsKeepMultipleValues(t *testing.T) {
	p := &OAuthProvider{
		ClientID:            "c",
		AuthorizationURL:    "https://idp.test/auth",
		AuthorizationParams: url.Values{"resource": {"a", "b"}, "prompt": {"consent"}},
	}
	u, err := url.Parse(authorizationURL(p, "https://app/cb", "", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if q := u.Query(); len(q["resource"]) != 2 || q.Get("prompt") != "consent" {
		t.Fatalf("query = %v", q)
	}
}
