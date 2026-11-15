package goauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

const hardeningSecret = "hardening-secret-hardening-secret"

func newHardeningAuth(t *testing.T, cfg Config) *Authorization {
	t.Helper()
	cfg.JWTSecret = hardeningSecret
	cfg.DB = &gorm.DB{}
	a, err := New(&cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func serveAPI(t *testing.T, a *Authorization, token string, next http.HandlerFunc) int {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	a.UseAPIAuthorization()(next).ServeHTTP(rec, req)
	return rec.Code
}

func TestNewValidatesConfigAtStartup(t *testing.T) {
	cases := map[string]Config{
		"bad access duration":  {AccessTokenDuration: "10 minutes"},
		"bad refresh duration": {RefreshTokenDuration: "1x"},
		"unknown algorithm":    {SigningMethod: "RS256"},
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

func TestAccessTokenRequiresExpiryAndConfiguredAlgorithm(t *testing.T) {
	a := newHardeningAuth(t, Config{}) // HS256
	ok := func(http.ResponseWriter, *http.Request) {}

	sign := func(method jwt.SigningMethod, claims jwt.MapClaims) string {
		s, err := jwt.NewWithClaims(method, claims).SignedString([]byte(hardeningSecret))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	exp := time.Now().Add(time.Minute).Unix()

	if code := serveAPI(t, a, sign(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": "u", "exp": exp}), ok); code != http.StatusOK {
		t.Fatalf("valid token: %d", code)
	}
	if code := serveAPI(t, a, sign(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": "u"}), ok); code != http.StatusUnauthorized {
		t.Fatalf("token without exp: %d, want 401", code)
	}
	if code := serveAPI(t, a, sign(jwt.SigningMethodHS512, jwt.MapClaims{"user_id": "u", "exp": exp}), ok); code != http.StatusUnauthorized {
		t.Fatalf("HS512 token on an HS256 config: %d, want 401", code)
	}
}

func TestClaimsAccessorsStayCompatible(t *testing.T) {
	a := newHardeningAuth(t, Config{})
	o := NewAuthorizeOptions(
		a.WithUserID("u1"),
		a.WithUserRoles(JSONBArray{"admin:rw", " hr:r "}),
		func(o *AuthorizeOptions) { o.content = JSONBAny{"plan": "pro"} },
	)
	access, _, err := a.SignTokenPair(o, "s1")
	if err != nil {
		t.Fatal(err)
	}

	var checked bool
	code := serveAPI(t, a, access, func(_ http.ResponseWriter, r *http.Request) {
		checked = true
		tok := JWTFromContext(r.Context())
		if tok == nil || !tok.Valid {
			t.Fatalf("JWTFromContext = %+v", tok)
		}
		claims, err := a.GetClaims(r)
		if err != nil {
			t.Fatal(err)
		}
		if claims["user_id"] != "u1" {
			t.Errorf("user_id = %v", claims["user_id"])
		}
		if content, _ := claims["content"].(map[string]any); content["plan"] != "pro" {
			t.Errorf("content claim lost: %v", claims["content"])
		}
		roles, err := a.GetRoles(r)
		if err != nil || len(roles) != 2 || roles[1] != "hr:r" {
			t.Errorf("GetRoles = %v, %v", roles, err)
		}
		data, err := a.GetAuthDataAPI(r)
		if err != nil || data.UserID != "u1" || len(data.Roles) != 2 {
			t.Errorf("GetAuthDataAPI = %+v, %v", data, err)
		}
	})
	if code != http.StatusOK || !checked {
		t.Fatalf("status %d, handler ran: %v", code, checked)
	}
}
