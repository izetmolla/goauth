package goauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gorm.io/gorm"
)

func benchAuth(b *testing.B) *Authorization {
	b.Helper()
	a, err := New(&Config{JWTSecret: "bench-secret-bench-secret-bench-secret", DB: &gorm.DB{}})
	if err != nil {
		b.Fatal(err)
	}
	return a
}

func benchTokens(b *testing.B, a *Authorization) (access, refresh string) {
	b.Helper()
	o := NewAuthorizeOptions(a.WithUserID("u1"), a.WithUserRoles(JSONBArray{"admin:rw", "hr:r"}))
	access, refresh, err := a.SignTokenPair(o, "s1")
	if err != nil {
		b.Fatal(err)
	}
	return access, refresh
}

// BenchmarkAPIMiddleware measures the per-request cost of a protected API
// route: bearer extraction, JWT verification, role decoding and the role gate.
func BenchmarkAPIMiddleware(b *testing.B) {
	a := benchAuth(b)
	access, _ := benchTokens(b, a)
	h := a.UseAPIAuthorization(a.WithRoles([]string{"admin"}))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/api/x", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	b.ReportAllocs()
	for b.Loop() {
		h.ServeHTTP(w, req)
	}
	if w.Code != http.StatusOK {
		b.Fatalf("status %d", w.Code)
	}
}

func BenchmarkSignTokenPair(b *testing.B) {
	a := benchAuth(b)
	o := NewAuthorizeOptions(a.WithUserID("u1"), a.WithUserRoles(JSONBArray{"admin:rw"}))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := a.SignTokenPair(o, "s1"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExtractRefreshToken(b *testing.B) {
	a := benchAuth(b)
	_, refresh := benchTokens(b, a)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := a.ExtractToken(refresh); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSessionCookie(b *testing.B) {
	a := benchAuth(b)
	b.ReportAllocs()
	for b.Loop() {
		_ = a.sessionCookie(true)
	}
}
