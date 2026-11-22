package goauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// enrollTOTPUser gives userID an enabled TOTP factor with the given backup codes.
func enrollTOTPUser(t *testing.T, a *Authorization, userID string, backups ...string) {
	t.Helper()
	key, err := a.totp.generateKey(userID)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := a.totp.encryptSecret([]byte(key.Secret()))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.upsertPendingTOTP(context.Background(), userID, enc); err != nil {
		t.Fatal(err)
	}
	hashes := make([]string, len(backups))
	for i, b := range backups {
		hashes[i] = a.totp.hashBackup(b)
	}
	if err := a.confirmTOTP(context.Background(), userID, enc, hashes); err != nil {
		t.Fatal(err)
	}
}

func TestBackupCodeCannotBeSpentTwiceConcurrently(t *testing.T) {
	a := newMFAAuth(t, openMFADB(t), true)
	enrollTOTPUser(t, a, "user-1", "AAAA1111", "BBBB2222")

	// Two requests load the factor before either writes, then both try the
	// same code: only the first may succeed.
	first, err := a.loadTotpFactor(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.loadTotpFactor(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	ok1, err := a.consumeBackupCode(context.Background(), first, "AAAA1111")
	if err != nil || !ok1 {
		t.Fatalf("first use: ok=%v err=%v", ok1, err)
	}
	ok2, err := a.consumeBackupCode(context.Background(), second, "AAAA1111")
	if err != nil || ok2 {
		t.Fatalf("second use of the same code must fail: ok=%v err=%v", ok2, err)
	}

	// The other code is still usable.
	if err := a.verifyTOTPOrBackup(context.Background(), "user-1", "BBBB2222"); err != nil {
		t.Fatalf("remaining code: %v", err)
	}
}

func TestMFAVerifyLocksOutAfterRepeatedWrongCodes(t *testing.T) {
	a := newMFAAuth(t, openMFADB(t), true)
	enrollTOTPUser(t, a, "user-1", "AAAA1111")
	h := a.Handler()
	token, err := a.issueMFAChallenge("user-1", "credentials", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	body := func(code string) string {
		b, _ := json.Marshal(map[string]string{"mfa_token": token, "code": code})
		return string(b)
	}

	for i := range mfaMaxFailures {
		rec := doJSON(t, h, http.MethodPost, DefaultBasePath+"/mfa/totp/verify", body("000000"), nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d %s", i+1, rec.Code, rec.Body.String())
		}
	}

	// Even a correct backup code is refused while locked out.
	rec := doJSON(t, h, http.MethodPost, DefaultBasePath+"/mfa/totp/verify", body("AAAA1111"), nil)
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), codeMFATooMany) {
		t.Fatalf("locked out: got %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}

	// The lockout expires after the window.
	a.totp.limiter.now = func() time.Time { return time.Now().Add(mfaFailureWindow + time.Second) }
	rec = doJSON(t, h, http.MethodPost, DefaultBasePath+"/mfa/totp/verify", body("AAAA1111"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("after window: got %d %s", rec.Code, rec.Body.String())
	}
}

func TestMFAChallengeRejectsValuesSignedForOtherPurposes(t *testing.T) {
	a := newMFAAuth(t, openMFADB(t), true)
	raw, _ := json.Marshal(mfaChallenge{UserID: "victim", Method: "credentials", Exp: time.Now().Add(time.Minute).Unix()})
	p := base64.RawURLEncoding.EncodeToString(raw)
	// A plain signValue(p) is what CSRF and flow-intent cookies use.
	forged := p + "." + signValue(p, a.JWTSecret)
	if _, err := a.decodeMFAChallenge(forged); err == nil {
		t.Fatal("a value signed without the MFA prefix must not decode")
	}
}

func TestLoginAsRefusesCrossSiteGet(t *testing.T) {
	db := openLoginAsDB(t)
	seedLoginAsUsers(t, db)
	a := newLoginAsAuth(t, db, true)
	adminSID, err := a.CreateSession(NewAuthorizeOptions(a.WithUserID("admin-1"), a.WithMethod("credentials")))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+"/login_as?user_id=user-2", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(&http.Cookie{Name: a.cookieSessionName, Value: adminSID})
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Header().Get("Set-Cookie"), a.cookieSessionName+"=") {
		t.Fatal("session cookie must not change")
	}
}

func TestLoginAsPostRequiresCSRFToken(t *testing.T) {
	db := openLoginAsDB(t)
	seedLoginAsUsers(t, db)
	a := newLoginAsAuth(t, db, true)
	adminSID, err := a.CreateSession(NewAuthorizeOptions(a.WithUserID("admin-1"), a.WithMethod("credentials")))
	if err != nil {
		t.Fatal(err)
	}
	h := a.Handler()

	post := func(body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultBasePath+"/login_as", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.AddCookie(&http.Cookie{Name: a.cookieSessionName, Value: adminSID})
		for _, c := range cookies {
			req.AddCookie(c)
		}
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := post(`{"user_id":"user-2"}`); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), codeCSRF) {
		t.Fatalf("without token: got %d %s", rec.Code, rec.Body.String())
	}

	// Fetch a CSRF token the way an SPA does, then retry.
	csrfRec := httptest.NewRecorder()
	h.ServeHTTP(csrfRec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+"/csrf", nil))
	var csrf struct {
		Token string `json:"csrfToken"`
	}
	if err := json.Unmarshal(csrfRec.Body.Bytes(), &csrf); err != nil || csrf.Token == "" {
		t.Fatalf("csrf: %v %s", err, csrfRec.Body.String())
	}
	body, _ := json.Marshal(map[string]string{"user_id": "user-2", "csrfToken": csrf.Token})
	rec := post(string(body), csrfRec.Result().Cookies()...)
	if rec.Code != http.StatusOK {
		t.Fatalf("with token: got %d %s", rec.Code, rec.Body.String())
	}
}
