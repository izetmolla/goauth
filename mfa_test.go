package goauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

type mfaTestUser struct {
	ID    string     `gorm:"primaryKey;size:64"`
	Roles JSONBArray `gorm:"type:text"`
}

func (mfaTestUser) TableName() string { return "users" }

func openMFADB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// Session tags use Postgres defaults (gen_random_uuid); create a portable schema for SQLite tests.
	if err := db.Exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  roles TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  type TEXT,
  ip_address TEXT,
  user_agent TEXT,
  method TEXT,
  logged_by TEXT,
  account TEXT,
  expires_at DATETIME,
  is_deleted NUMERIC DEFAULT 0,
  created_at DATETIME,
  updated_at DATETIME,
  deleted_at DATETIME
);
CREATE TABLE IF NOT EXISTS goauth_totp (
  user_id TEXT PRIMARY KEY,
  secret_enc BLOB NOT NULL,
  enabled NUMERIC NOT NULL DEFAULT 0,
  backup_hashes TEXT,
  confirmed_at DATETIME,
  disabled_at DATETIME,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);`).Error; err != nil {
		t.Fatal(err)
	}
	return db
}

func newMFAAuth(t *testing.T, db *gorm.DB, enabled bool) *Authorization {
	t.Helper()
	a, err := New(&Config{
		JWTSecret: "mfa-test-secret-at-least-32-chars!!",
		DB:        db,
		Providers: []Provider{
			&CredentialsProvider{
				ProviderID: "credentials",
				Authorize: func(context.Context, map[string]string, *http.Request) (*OAuthUser, error) {
					return &OAuthUser{ID: "user-1", Email: "a@b.c"}, nil
				},
			},
		},
		MFA: MFAOptions{TOTP: TOTPOptions{Enabled: enabled, Issuer: "TestApp"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		if err := a.MigrateTOTP(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

func seedUserSession(t *testing.T, a *Authorization, userID string) (sessionID string, cookie *http.Cookie) {
	t.Helper()
	if err := a.db.Create(&mfaTestUser{ID: userID, Roles: JSONBArray{}}).Error; err != nil {
		t.Fatal(err)
	}
	sid, err := a.CreateSession(NewAuthorizeOptions(a.WithUserID(userID), a.WithMethod("credentials")))
	if err != nil {
		t.Fatal(err)
	}
	return sid, &http.Cookie{Name: a.cookieSessionName, Value: sid}
}

func TestTOTPEncryptRoundTrip(t *testing.T) {
	m, err := newTOTP(TOTPOptions{Enabled: true, Issuer: "App"}, "secret-secret-secret-secret-secret", "App", DefaultTablePrefix)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := m.encryptSecret([]byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := m.decryptSecret(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("got %q", plain)
	}
}

func TestMFAChallengeRoundTrip(t *testing.T) {
	a := newMFAAuth(t, openMFADB(t), true)
	tok, err := a.issueMFAChallenge("user-1", "credentials", "/home", nil)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := a.decodeMFAChallenge(tok)
	if err != nil {
		t.Fatal(err)
	}
	if ch.UserID != "user-1" || ch.Method != "credentials" || ch.Redirect != "/home" {
		t.Fatalf("unexpected challenge: %+v", ch)
	}
	if _, err := a.decodeMFAChallenge(tok + "x"); err == nil {
		t.Fatal("expected invalid token")
	}
}

func TestMFARoutesOffByDefault(t *testing.T) {
	a := newMFAAuth(t, openMFADB(t), false)
	h := a.Handler()
	for _, path := range []string{
		"/mfa/totp/status",
		"/mfa/totp/enroll/begin",
		"/mfa/totp/enroll/confirm",
		"/mfa/totp/disable",
		"/mfa/totp/verify",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+path, nil)
		if strings.Contains(path, "enroll") || strings.Contains(path, "disable") || strings.Contains(path, "verify") {
			req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultBasePath+path, nil)
		}
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d", path, rec.Code)
		}
	}
}

func TestTOTPEnrollConfirmDisableAndChallenge(t *testing.T) {
	db := openMFADB(t)
	a := newMFAAuth(t, db, true)
	h := a.Handler()
	_, cookie := seedUserSession(t, a, "user-1")

	// enroll begin
	begin := doJSON(t, h, http.MethodPost, DefaultBasePath+"/mfa/totp/enroll/begin", `{"account":"a@b.c"}`, cookie)
	if begin.Code != http.StatusOK {
		t.Fatalf("begin: %d %s", begin.Code, begin.Body.String())
	}
	var beginBody struct {
		Secret     string `json:"secret"`
		OtpauthURL string `json:"otpauth_url"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &beginBody); err != nil || beginBody.Secret == "" || beginBody.OtpauthURL == "" {
		t.Fatalf("begin body: %v %s", err, begin.Body.String())
	}

	code, err := totp.GenerateCode(beginBody.Secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	confirm := doJSON(t, h, http.MethodPost, DefaultBasePath+"/mfa/totp/enroll/confirm", `{"code":"`+code+`"}`, cookie)
	if confirm.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", confirm.Code, confirm.Body.String())
	}
	var confirmBody struct {
		Enabled     bool     `json:"enabled"`
		BackupCodes []string `json:"backup_codes"`
	}
	if err := json.Unmarshal(confirm.Body.Bytes(), &confirmBody); err != nil || !confirmBody.Enabled || len(confirmBody.BackupCodes) == 0 {
		t.Fatalf("confirm body: %v %s", err, confirm.Body.String())
	}

	status := doJSON(t, h, http.MethodGet, DefaultBasePath+"/mfa/totp/status", "", cookie)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"enabled":true`) {
		t.Fatalf("status: %d %s", status.Code, status.Body.String())
	}

	// finishSignIn challenges
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultBasePath+"/provider/credentials", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Auth-Flow", "token")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("sign-in: %d %s", rec.Code, rec.Body.String())
	}
	var challenge struct {
		Code string `json:"code"`
		MFA  struct {
			Token string `json:"token"`
		} `json:"mfa"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &challenge); err != nil || challenge.Code != codeMFARequired || challenge.MFA.Token == "" {
		t.Fatalf("challenge: %v %s", err, rec.Body.String())
	}

	verifyCode, err := totp.GenerateCode(beginBody.Secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	verifyBody, _ := json.Marshal(map[string]string{"mfa_token": challenge.MFA.Token, "code": verifyCode})
	verify := doJSON(t, h, http.MethodPost, DefaultBasePath+"/mfa/totp/verify", string(verifyBody), nil)
	if verify.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", verify.Code, verify.Body.String())
	}
	if !strings.Contains(verify.Body.String(), `"type":"sign_in"`) {
		t.Fatalf("verify payload: %s", verify.Body.String())
	}

	// disable with a backup code
	disableBody, _ := json.Marshal(map[string]string{"code": confirmBody.BackupCodes[0]})
	dis := doJSON(t, h, http.MethodPost, DefaultBasePath+"/mfa/totp/disable", string(disableBody), cookie)
	if dis.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", dis.Code, dis.Body.String())
	}

	// sign-in no longer challenges
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultBasePath+"/provider/credentials", strings.NewReader(`{}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Accept", "application/json")
	req2.Header.Set("X-Auth-Flow", "token")
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), `"type":"sign_in"`) {
		t.Fatalf("sign-in after disable: %d %s", rec2.Code, rec2.Body.String())
	}
}

func TestMaybeChallengeMFAForCompleteSignIn(t *testing.T) {
	db := openMFADB(t)
	a := newMFAAuth(t, db, true)
	if err := a.db.Create(&mfaTestUser{ID: "user-oauth", Roles: JSONBArray{}}).Error; err != nil {
		t.Fatal(err)
	}
	m, err := newTOTP(TOTPOptions{Enabled: true, Issuer: "App"}, a.JWTSecret, "App", DefaultTablePrefix)
	if err != nil {
		t.Fatal(err)
	}
	key, err := m.generateKey("user-oauth")
	if err != nil {
		t.Fatal(err)
	}
	enc, err := m.encryptSecret([]byte(key.Secret()))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.upsertPendingTOTP(context.Background(), "user-oauth", enc); err != nil {
		t.Fatal(err)
	}
	if err := a.confirmTOTP(context.Background(), "user-oauth", enc, []string{a.totp.hashBackup("BACKUP01")}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	a.completeSignIn(rec, req, &OAuthProvider{ProviderID: "google", DisplayName: "Google"}, &User{ID: "user-oauth"}, &Account{Provider: "google", ProviderAccountID: "1"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), codeMFARequired) {
		t.Fatalf("body: %s", rec.Body.String())
	}
}

func doJSON(t *testing.T, h http.Handler, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequestWithContext(t.Context(), method, path, nil)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Auth-Flow", "token")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	h.ServeHTTP(rec, req)
	return rec
}
