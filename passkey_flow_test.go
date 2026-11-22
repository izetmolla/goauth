package goauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gorm.io/gorm"
)

type stubCeremony struct {
	beginLoginOpts any
	beginLoginID   string
	finishUser     *OAuthUser
	finishErr      error
	finishCalled   bool
}

func (s *stubCeremony) BeginRegister(context.Context, string, string, string) (any, string, error) {
	return map[string]string{"op": "create"}, "reg-chal", nil
}
func (s *stubCeremony) FinishRegister(context.Context, string, string, io.Reader) error {
	return nil
}
func (s *stubCeremony) BeginLogin(context.Context) (any, string, error) {
	return s.beginLoginOpts, s.beginLoginID, nil
}
func (s *stubCeremony) FinishLogin(context.Context, string, io.Reader) (*OAuthUser, error) {
	s.finishCalled = true
	return s.finishUser, s.finishErr
}

func passkeyAuth(t *testing.T, ceremony PasskeyCeremony) *Authorization {
	t.Helper()
	a, err := New(&Config{
		JWTSecret: "test-secret-at-least-32-chars-long!!",
		AuthURL:   "http://localhost",
		DB:        &gorm.DB{},
		Providers: []Provider{
			&PasskeyProvider{
				ProviderID:  "passkey",
				DisplayName: "Passkey",
				Ceremony:    ceremony,
			},
		},
		ResolveUser: func(context.Context, Profile) (*User, bool, error) {
			return &User{ID: "user-1"}, false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPasskeyLoginBegin(t *testing.T) {
	a := passkeyAuth(t, &stubCeremony{
		beginLoginOpts: map[string]any{"challenge": "abc"},
		beginLoginID:   "login-chal",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultBasePath+"/provider/passkey/login/begin", nil)
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin = %d %s", rec.Code, rec.Body.String())
	}
	var begin map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	if begin["challengeId"] != "login-chal" {
		t.Fatalf("begin body = %#v", begin)
	}
	if begin["options"] == nil {
		t.Fatal("missing options")
	}
}

func TestPasskeyLoginFinish_RejectsBadAssertion(t *testing.T) {
	stub := &stubCeremony{finishErr: errPasskeyDenied}
	a := passkeyAuth(t, stub)
	rec := httptest.NewRecorder()
	body := `{"challengeId":"login-chal","credential":{"id":"x"}}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultBasePath+"/provider/passkey/login/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	a.Handler().ServeHTTP(rec, req)
	if !stub.finishCalled {
		t.Fatal("FinishLogin not called")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("finish = %d %s", rec.Code, rec.Body.String())
	}
}

func TestPasskeyRegisterRequiresAuth(t *testing.T) {
	a := passkeyAuth(t, &stubCeremony{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultBasePath+"/provider/passkey/register/begin", nil)
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("register begin without auth = %d", rec.Code)
	}
}

func TestPasskeyProviderPathHintsCeremony(t *testing.T) {
	a := passkeyAuth(t, &stubCeremony{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, DefaultBasePath+"/provider/passkey", nil)
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "login|register") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

var errPasskeyDenied = errString("denied")

type errString string

func (e errString) Error() string { return string(e) }
