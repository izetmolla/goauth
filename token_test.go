package goauth

import (
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGetTokenFromHeader(t *testing.T) {
	a := &Authorization{}

	tests := []struct {
		name    string
		header  string
		want    string
		wantErr bool
	}{
		{name: "bearer scheme", header: "Bearer abc.def.ghi", want: "abc.def.ghi"},
		{name: "bearer scheme lowercase", header: "bearer abc.def.ghi", want: "abc.def.ghi"},
		{name: "token scheme", header: "Token abc.def.ghi", want: "abc.def.ghi"},
		{name: "no scheme returns as-is", header: "abc.def.ghi", want: "abc.def.ghi"},
		{name: "empty header errors", header: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := a.GetTokenFromHeader(tt.header)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("GetTokenFromHeader(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestSignTokenPairRoundTrip(t *testing.T) {
	a := &Authorization{
		JWTSecret:            "test-secret",
		accessTokenDuration:  "5m",
		refreshTokenDuration: "7d",
	}
	opts := NewAuthorizeOptions(
		a.WithUserID("user-1"),
		a.WithUserRoles(JSONBArray{"admin:rw", "hr:r"}),
	)

	accessToken, refreshToken, err := a.SignTokenPair(opts, "session-1")
	if err != nil {
		t.Fatalf("SignTokenPair: %v", err)
	}

	refreshClaims, err := a.ExtractToken(refreshToken)
	if err != nil {
		t.Fatalf("ExtractToken(refresh): %v", err)
	}
	if refreshClaims.SessionID != "session-1" {
		t.Errorf("refresh SessionID = %q, want %q", refreshClaims.SessionID, "session-1")
	}
	if refreshClaims.UserID != "user-1" {
		t.Errorf("refresh UserID = %q, want %q", refreshClaims.UserID, "user-1")
	}

	// "tokenlife" must describe the ACCESS token lifetime (5m), not the
	// refresh token duration (7d).
	if want := (5 * time.Minute).String(); refreshClaims.AccessTokenLifetime != want {
		t.Errorf("AccessTokenLifetime = %q, want %q", refreshClaims.AccessTokenLifetime, want)
	}

	var accessClaims Claims
	token, err := jwt.ParseWithClaims(accessToken, &accessClaims, a.keyFunc)
	if err != nil || !token.Valid {
		t.Fatalf("parse access token: %v (valid=%v)", err, token != nil && token.Valid)
	}
	if accessClaims.UserID != "user-1" {
		t.Errorf("access UserID = %q, want %q", accessClaims.UserID, "user-1")
	}
	gotRoles := FormatRoles(accessClaims.Roles)
	if want := []string{"admin:rw", "hr:r"}; !reflect.DeepEqual(gotRoles, want) {
		t.Errorf("access roles = %v, want %v", gotRoles, want)
	}

	// Access token must expire well before the refresh token.
	if !accessClaims.ExpiresAt.Before(refreshClaims.ExpiresAt.Time) {
		t.Errorf("access token expiry %v is not before refresh token expiry %v",
			accessClaims.ExpiresAt.Time, refreshClaims.ExpiresAt.Time)
	}
}
