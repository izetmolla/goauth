package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func testVerificationAuth(t *testing.T) *Authorization {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:ver_"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	find := func(context.Context, string) (*OAuthUser, error) {
		return &OAuthUser{ID: "u1", Email: "a@x.io"}, nil
	}
	send := func(context.Context, *VerificationMessage) error { return nil }
	set := func(context.Context, string, string) error { return nil }
	a, err := New(&Config{
		JWTSecret: "test-secret-at-least-32-chars-long!!",
		AuthURL:   "http://localhost",
		DB:        db,
		UI:        UIOptions{EnableAllUI: true, ForgotPasswordEndpoint: "/forgot-password"},
		Verification: VerificationOptions{
			PasswordReset: PasswordResetOptions{
				Enabled: true,
				Code: CodeOptions{
					TTL:      15 * time.Minute,
					Delivery: DeliverCodeAndLink,
				},
			},
			FindUser:    find,
			Send:        send,
			SetPassword: set,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.MigrateVerificationTokens(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestFindLiveExpiredAndUsed(t *testing.T) {
	a := testVerificationAuth(t)
	ctx := context.Background()
	f := &a.verify.reset
	now := time.Now().UTC()

	expiredID := "11111111-1111-4111-8111-111111111111"
	usedID := "22222222-2222-4222-8222-222222222222"
	liveID := "33333333-3333-4333-8333-333333333333"
	consumed := now.Add(-time.Minute)

	rows := []VerificationToken{
		{ID: expiredID, Kind: KindPasswordReset, Identifier: "a@x.io", UserID: "u1", TokenHash: a.verify.tokenHash(KindPasswordReset, "expired-tok"), ExpiresAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour)},
		{ID: usedID, Kind: KindPasswordReset, Identifier: "a@x.io", UserID: "u1", TokenHash: a.verify.tokenHash(KindPasswordReset, "used-tok"), ExpiresAt: now.Add(time.Hour), ConsumedAt: &consumed, CreatedAt: now.Add(-time.Hour)},
		{ID: liveID, Kind: KindPasswordReset, Identifier: "a@x.io", UserID: "u1", TokenHash: a.verify.tokenHash(KindPasswordReset, "live-tok"), ExpiresAt: now.Add(time.Hour), CreatedAt: now},
	}
	for _, row := range rows {
		if err := a.verificationTable(ctx).Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}

	if _, err := a.findLive(ctx, f, verifyInput{vid: expiredID}); !errors.Is(err, ErrVerificationExpired) {
		t.Fatalf("expired vid: got %v", err)
	}
	if _, err := a.findLive(ctx, f, verifyInput{token: "expired-tok"}); !errors.Is(err, ErrVerificationExpired) {
		t.Fatalf("expired token: got %v", err)
	}
	if _, err := a.findLive(ctx, f, verifyInput{vid: usedID}); !errors.Is(err, ErrVerificationUsed) {
		t.Fatalf("used vid: got %v", err)
	}
	if _, err := a.findLive(ctx, f, verifyInput{token: "used-tok"}); !errors.Is(err, ErrVerificationUsed) {
		t.Fatalf("used token: got %v", err)
	}
	row, err := a.findLive(ctx, f, verifyInput{token: "live-tok"})
	if err != nil || row.ID != liveID {
		t.Fatalf("live token: row=%v err=%v", row, err)
	}
}

func TestConsumeVerificationIsSingleUse(t *testing.T) {
	a := testVerificationAuth(t)
	ctx := context.Background()
	f := &a.verify.reset
	now := time.Now().UTC()
	id := "44444444-4444-4444-8444-444444444444"
	row := VerificationToken{
		ID: id, Kind: KindPasswordReset, Identifier: "a@x.io", UserID: "u1",
		TokenHash: a.verify.tokenHash(KindPasswordReset, "once"),
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	if err := a.verificationTable(ctx).Create(&row).Error; err != nil {
		t.Fatal(err)
	}

	if _, err := a.consumeVerification(ctx, f, verifyInput{vid: id, token: "once"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.consumeVerification(ctx, f, verifyInput{vid: id, token: "once"}); !errors.Is(err, ErrVerificationUsed) {
		t.Fatalf("reuse: got %v, want used", err)
	}
}

func TestHandleResetCheckRejectsUsedToken(t *testing.T) {
	a := testVerificationAuth(t)
	ctx := context.Background()
	now := time.Now().UTC()
	id := "77777777-7777-4777-8777-777777777777"
	tok := "check-tok"
	consumed := now.Add(-time.Minute)
	row := VerificationToken{
		ID: id, Kind: KindPasswordReset, Identifier: "a@x.io", UserID: "u1",
		TokenHash: a.verify.tokenHash(KindPasswordReset, tok),
		ExpiresAt: now.Add(time.Hour), ConsumedAt: &consumed, CreatedAt: now.Add(-time.Hour),
	}
	if err := a.verificationTable(ctx).Create(&row).Error; err != nil {
		t.Fatal(err)
	}

	h := a.Handler()
	csrfRec := httptest.NewRecorder()
	h.ServeHTTP(csrfRec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+"/csrf", nil))
	var csrfBody map[string]string
	_ = json.NewDecoder(csrfRec.Body).Decode(&csrfBody)

	body := url.Values{
		"vid": {id}, "token": {tok}, "csrfToken": {csrfBody["csrfToken"]},
	}.Encode()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultBasePath+"/password/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	for _, c := range csrfRec.Result().Cookies() {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["code"] != codeCodeUsed {
		t.Fatalf("code=%v want %s body=%s", out["code"], codeCodeUsed, rec.Body.String())
	}
}

func TestHandleResetPasswordSignsIn(t *testing.T) {
	a := testVerificationAuth(t)
	ctx := context.Background()
	if err := a.db.Exec(`
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
);`).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	id := "88888888-8888-4888-8888-888888888888"
	tok := "reset-signin-tok"
	row := VerificationToken{
		ID: id, Kind: KindPasswordReset, Identifier: "a@x.io", UserID: "u1",
		TokenHash: a.verify.tokenHash(KindPasswordReset, tok),
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	if err := a.verificationTable(ctx).Create(&row).Error; err != nil {
		t.Fatal(err)
	}

	h := a.Handler()
	csrfRec := httptest.NewRecorder()
	h.ServeHTTP(csrfRec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+"/csrf", nil))
	var csrfBody map[string]string
	_ = json.NewDecoder(csrfRec.Body).Decode(&csrfBody)

	body := url.Values{
		"vid": {id}, "token": {tok}, "password": {"NewPass1!"},
		"password_confirm": {"NewPass1!"}, "redirectUrl": {"/projects"},
		"csrfToken": {csrfBody["csrfToken"]},
	}.Encode()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultBasePath+"/password/reset", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	for _, c := range csrfRec.Result().Cookies() {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["type"] != "sign_in" {
		t.Fatalf("type=%v want sign_in body=%s", out["type"], rec.Body.String())
	}
	if out["redirect_url"] != "/projects" {
		t.Fatalf("redirect_url=%v want /projects", out["redirect_url"])
	}
	if out["session_id"] == nil || out["session_id"] == "" {
		t.Fatalf("missing session_id: %v", out)
	}
}

func TestConsumeSiblingVerifications(t *testing.T) {
	a := testVerificationAuth(t)
	ctx := context.Background()
	f := &a.verify.reset
	now := time.Now().UTC()
	keep := "55555555-5555-4555-8555-555555555555"
	other := "66666666-6666-4666-8666-666666666666"
	for _, id := range []string{keep, other} {
		row := VerificationToken{
			ID: id, Kind: KindPasswordReset, Identifier: "a@x.io", UserID: "u1",
			TokenHash: a.verify.tokenHash(KindPasswordReset, id),
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}
		if err := a.verificationTable(ctx).Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := a.consumeSiblingVerifications(ctx, f, "a@x.io", keep); err != nil {
		t.Fatal(err)
	}
	if _, err := a.findLive(ctx, f, verifyInput{vid: other}); !errors.Is(err, ErrVerificationUsed) {
		t.Fatalf("sibling should be used, got %v", err)
	}
	if _, err := a.findLive(ctx, f, verifyInput{vid: keep}); err != nil {
		t.Fatalf("kept row should stay live: %v", err)
	}
}
