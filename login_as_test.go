package goauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

func openLoginAsDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:loginas_"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
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
);`).Error; err != nil {
		t.Fatal(err)
	}
	return db
}

func seedLoginAsUsers(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, u := range []mfaTestUser{
		{ID: "admin-1", Roles: JSONBArray{"admin:rw"}},
		{ID: "user-2", Roles: JSONBArray{"user:r"}},
		{ID: "user-3", Roles: JSONBArray{"user:r"}},
	} {
		if err := db.Create(&u).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func newLoginAsAuth(t *testing.T, db *gorm.DB, enabled bool) *Authorization {
	t.Helper()
	cfg := &Config{
		JWTSecret: "login-as-secret-at-least-32-chars!",
		DB:        db,
		UI:        UIOptions{DefaultRedirect: "/home"},
		Providers: []Provider{&CredentialsProvider{ProviderID: "credentials"}},
	}
	if enabled {
		cfg.LoginAs = LoginAsOptions{
			Enabled: true,
			Roles:   []string{"admin"},
			ResolveUser: func(_ context.Context, userID string) (*LoginAsUser, error) {
				switch userID {
				case "admin-1":
					return &LoginAsUser{ID: "admin-1", Name: "Ada Admin", Email: "ada@example.com"}, nil
				case "user-2":
					return &LoginAsUser{ID: "user-2", Name: "Bob User", Email: "bob@example.com"}, nil
				case "user-3":
					return &LoginAsUser{ID: "user-3", Email: "carol@example.com"}, nil
				default:
					return nil, nil
				}
			},
		}
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestLoginAsDisabledByDefault(t *testing.T) {
	a := newLoginAsAuth(t, openLoginAsDB(t), false)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+"/login_as?user_id=user-2", nil)
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestLoginAsRequiresRolesConfig(t *testing.T) {
	_, err := New(&Config{
		JWTSecret: "login-as-secret-at-least-32-chars!",
		DB:        openLoginAsDB(t),
		Providers: []Provider{&CredentialsProvider{ProviderID: "credentials"}},
		LoginAs: LoginAsOptions{
			Enabled: true,
			ResolveUser: func(context.Context, string) (*LoginAsUser, error) {
				return nil, nil
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for missing Roles")
	}
}

func TestLoginAsSuccessSetsSessionAndTokens(t *testing.T) {
	db := openLoginAsDB(t)
	seedLoginAsUsers(t, db)
	a := newLoginAsAuth(t, db, true)

	adminSID, err := a.CreateSession(NewAuthorizeOptions(a.WithUserID("admin-1"), a.WithMethod("credentials")))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+"/login_as?user_id=user-2", nil)
	req.Header.Set("Accept", "application/json")
	req.AddCookie(&http.Cookie{Name: a.cookieSessionName, Value: adminSID})
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Code      string `json:"code"`
		Type      string `json:"type"`
		SessionID string `json:"session_id"`
		LoggedBy  struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"logged_by"`
		Tokens Tokens `json:"tokens"`
		User   struct {
			ID string `json:"id"`
		} `json:"user"`
		Redirect string `json:"redirect_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Type != "sign_in" || body.User.ID != "user-2" {
		t.Fatalf("body: %+v", body)
	}
	if body.LoggedBy.ID != "admin-1" || body.LoggedBy.Name != "Ada Admin" {
		t.Fatalf("logged_by: %+v", body.LoggedBy)
	}
	if body.Redirect != "/home" {
		t.Fatalf("redirect = %q", body.Redirect)
	}

	var sess Session
	if err := db.Table("sessions").Where("id = ?", body.SessionID).Take(&sess).Error; err != nil {
		t.Fatal(err)
	}
	if sess.UserID != "user-2" || sess.LoggedBy == nil || *sess.LoggedBy != "admin-1" {
		t.Fatalf("session: user=%q logged_by=%v", sess.UserID, sess.LoggedBy)
	}
	if sess.Method != methodLoginAs {
		t.Fatalf("method = %q", sess.Method)
	}

	var access Claims
	tok, err := jwt.ParseWithClaims(body.Tokens.AccessToken, &access, a.keyFunc)
	if err != nil || !tok.Valid {
		t.Fatalf("access token: %v", err)
	}
	if access.UserID != "user-2" || access.LoggedBy == nil || access.LoggedBy.ID != "admin-1" || access.LoggedBy.Name != "Ada Admin" {
		t.Fatalf("access claims: %+v", access)
	}
	refresh, err := a.ExtractToken(body.Tokens.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if refresh.LoggedBy == nil || refresh.LoggedBy.ID != "admin-1" {
		t.Fatalf("refresh logged_by: %+v", refresh.LoggedBy)
	}
}

func TestLoginAsForbiddenForNonAdmin(t *testing.T) {
	db := openLoginAsDB(t)
	seedLoginAsUsers(t, db)
	a := newLoginAsAuth(t, db, true)
	sid, err := a.CreateSession(NewAuthorizeOptions(a.WithUserID("user-2")))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+"/login_as?user_id=user-3", nil)
	req.Header.Set("Accept", "application/json")
	req.AddCookie(&http.Cookie{Name: a.cookieSessionName, Value: sid})
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestLoginAsTargetNotFound(t *testing.T) {
	db := openLoginAsDB(t)
	seedLoginAsUsers(t, db)
	a := newLoginAsAuth(t, db, true)
	sid, err := a.CreateSession(NewAuthorizeOptions(a.WithUserID("admin-1")))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+"/login_as?user_id=missing", nil)
	req.Header.Set("Accept", "application/json")
	req.AddCookie(&http.Cookie{Name: a.cookieSessionName, Value: sid})
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestLoginAsSwitchWhileImpersonating(t *testing.T) {
	db := openLoginAsDB(t)
	seedLoginAsUsers(t, db)
	a := newLoginAsAuth(t, db, true)
	admin := "admin-1"
	sid, err := a.CreateSession(NewAuthorizeOptions(
		a.WithUserID("user-2"),
		a.WithLoggedBy(&LoggedBy{ID: admin, Name: "Ada Admin"}),
	))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+"/login_as?user_id=user-3", nil)
	req.Header.Set("Accept", "application/json")
	req.AddCookie(&http.Cookie{Name: a.cookieSessionName, Value: sid})
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		LoggedBy LoggedBy `json:"logged_by"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.User.ID != "user-3" || body.LoggedBy.ID != admin {
		t.Fatalf("body: %+v", body)
	}
}
