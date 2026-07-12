package goauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			r := httptest.NewRequest(http.MethodGet, "/protected", nil)
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
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	protected := a.UseAPIAuthorization(a.WithExcludedPaths([]string{"/public"}))(next)

	r := httptest.NewRequest(http.MethodGet, "/public/health", nil)
	w := httptest.NewRecorder()
	protected.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("excluded path status = %d, want %d", w.Code, http.StatusOK)
	}
}
