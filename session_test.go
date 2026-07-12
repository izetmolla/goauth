package goauth

import (
	"errors"
	"testing"
	"time"
)

func TestSessionUsable(t *testing.T) {
	tests := []struct {
		name    string
		session *Session
		wantErr error
	}{
		{
			name:    "nil session",
			session: nil,
			wantErr: ErrSessionNotFound,
		},
		{
			name:    "soft-deleted session",
			session: &Session{ID: "s1", IsDeleted: true, ExpiresAt: time.Now().Add(time.Hour)},
			wantErr: ErrSessionNotFound,
		},
		{
			name:    "expired session",
			session: &Session{ID: "s1", ExpiresAt: time.Now().Add(-time.Minute)},
			wantErr: ErrSessionExpired,
		},
		{
			name:    "active session",
			session: &Session{ID: "s1", ExpiresAt: time.Now().Add(time.Hour)},
			wantErr: nil,
		},
		{
			name:    "zero expiry never expires",
			session: &Session{ID: "s1"},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sessionUsable(tt.session)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("sessionUsable() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
