package goauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

func signTestAccessToken(t *testing.T, secret string, roles any) string {
	t.Helper()
	claims := jwt.MapClaims{
		"user_id": "user-1",
		"roles":   roles,
		"exp":     time.Now().Add(time.Minute).Unix(),
		"iat":     time.Now().Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	return token
}

func TestUseAPIAuthorization(t *testing.T) {
	const secret = "test-secret"
	a := &Authorization{JWTSecret: secret}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	protected := a.UseAPIAuthorization(a.WithRoles([]string{"admin"}))(next)

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{
			name:       "valid token with matching role",
			authHeader: "Bearer " + signTestAccessToken(t, secret, []any{"admin:rw"}),
			wantStatus: http.StatusOK,
		},
		{
			// Regression: a null entry in the roles claim used to bubble up
			// as a 500 from rolesFromAny.
			name:       "roles claim containing null entries",
			authHeader: "Bearer " + signTestAccessToken(t, secret, []any{nil, "admin:rw"}),
			wantStatus: http.StatusOK,
		},
		{
			// Regression: a JSON-encoded roles string used to be wrapped as a
			// single garbage grant, denying access.
			name:       "roles claim as json-encoded string",
			authHeader: "Bearer " + signTestAccessToken(t, secret, `["admin:rw","hr:r"]`),
			wantStatus: http.StatusOK,
		},
		{
			name:       "valid token without required role",
			authHeader: "Bearer " + signTestAccessToken(t, secret, []any{"hr:r"}),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "missing token",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "token signed with wrong secret",
			authHeader: "Bearer " + signTestAccessToken(t, "other-secret", []any{"admin:rw"}),
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected", nil)
			if tt.authHeader != "" {
				r.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()
			protected.ServeHTTP(w, r)
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

func TestUseAPIAuthorizationExcludedPath(t *testing.T) {
	a := &Authorization{JWTSecret: "test-secret"}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	protected := a.UseAPIAuthorization(a.WithExcludedPaths([]string{"/public"}))(next)

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/public/health", nil)
	w := httptest.NewRecorder()
	protected.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("excluded path status = %d, want %d", w.Code, http.StatusOK)
	}
}

func openReauthorizeDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:reauth_"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), &gorm.Config{})
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

func TestUseAPIAuthorizationReauthorizeFromCookie(t *testing.T) {
	db := openReauthorizeDB(t)
	if err := db.Exec(`INSERT INTO users (id, roles) VALUES (?, ?)`, "user-1", `["user:rw"]`).Error; err != nil {
		t.Fatal(err)
	}
	a, err := New(&Config{
		JWTSecret:                  "reauthorize-secret-at-least-32-chars!!",
		DB:                         db,
		KeepRefreshTokenServerSide: true,
		AccessTokenDuration:        "60s",
		RefreshTokenDuration:       "1h",
	})
	if err != nil {
		t.Fatal(err)
	}
	sid, err := a.CreateSession(NewAuthorizeOptions(a.WithUserID("user-1"), a.WithUserRoles(JSONBArray{"user:rw"})))
	if err != nil {
		t.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	protected := a.UseAPIAuthorization(a.WithReauthorize())(next)

	t.Run("cra without cookie is still 401", func(t *testing.T) {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/test", nil)
		r.Header.Set(ReauthorizeHandlerIdentifier, "t")
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (body: %s)", w.Code, w.Body.String())
		}
	})

	t.Run("cra with session cookie returns reauthorize payload", func(t *testing.T) {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/test", nil)
		r.Header.Set(ReauthorizeHandlerIdentifier, "t")
		r.AddCookie(&http.Cookie{Name: a.cookieSessionName, Value: sid})
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		var payload struct {
			Reauthorize bool   `json:"reauthorize"`
			SessionID   string `json:"session_id"`
			User        struct {
				ID string `json:"id"`
			} `json:"user"`
			Tokens Tokens `json:"tokens"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !payload.Reauthorize || payload.SessionID != sid || payload.User.ID != "user-1" {
			t.Fatalf("payload = %+v", payload)
		}
		if payload.Tokens.AccessToken == "" || payload.Tokens.RefreshToken == "" {
			t.Fatalf("tokens = %+v", payload.Tokens)
		}
		if _, err := a.parseAccessToken(payload.Tokens.AccessToken); err != nil {
			t.Fatalf("access token: %v", err)
		}
		refreshClaims, err := a.ExtractToken(payload.Tokens.RefreshToken)
		if err != nil {
			t.Fatalf("refresh token: %v", err)
		}
		if refreshClaims.SessionID != sid || refreshClaims.UserID != "user-1" {
			t.Fatalf("refresh claims = %+v", refreshClaims)
		}
	})

	t.Run("valid bearer still reaches the handler", func(t *testing.T) {
		access := signTestAccessToken(t, a.JWTSecret, []any{"user:rw"})
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/test", nil)
		r.Header.Set("Authorization", "Bearer "+access)
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, r)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok":true`) {
			t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
		}
	})
}

// Regression: a long-lived refresh token must not be accepted as an access
// token, including legacy refresh tokens minted without a token_type claim.
func TestUseAPIAuthorizationRejectsRefreshTokens(t *testing.T) {
	a := &Authorization{JWTSecret: "test-secret", accessTokenDuration: "5m", refreshTokenDuration: "7d"}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	protected := a.UseAPIAuthorization()(next)

	access, refresh, err := a.SignTokenPair(NewAuthorizeOptions(a.WithUserID("user-1")), "session-1")
	if err != nil {
		t.Fatalf("SignTokenPair: %v", err)
	}
	legacyRefresh, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"session_id": "session-1",
		"user_id":    "user-1",
		"exp":        time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(a.JWTSecret))
	if err != nil {
		t.Fatalf("sign legacy refresh token: %v", err)
	}

	tests := []struct {
		name       string
		token      string
		wantStatus int
	}{
		{name: "access token", token: access, wantStatus: http.StatusOK},
		{name: "refresh token", token: refresh, wantStatus: http.StatusUnauthorized},
		{name: "legacy refresh token", token: legacyRefresh, wantStatus: http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected", nil)
			r.Header.Set("Authorization", "Bearer "+tt.token)
			w := httptest.NewRecorder()
			protected.ServeHTTP(w, r)
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}
