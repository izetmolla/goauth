package passkey

import (
	"context"
	"testing"

	"github.com/izetmolla/goauth"
)

func TestNew_RequiresConfig(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{}); err == nil {
		t.Fatal("expected error for empty options")
	}
	if _, err := New(Options{Store: NewMemoryStore(), RPID: "localhost"}); err == nil {
		t.Fatal("expected error without origins")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	p, err := New(Options{
		RPDisplayName: "Test",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:3000"},
		Store:         NewMemoryStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	pp, ok := p.(*goauth.PasskeyProvider)
	if !ok {
		t.Fatalf("type = %T", p)
	}
	if pp.ID() != ID || pp.Name() != "Passkey" || pp.Type() != goauth.ProviderPasskey {
		t.Fatalf("id/name/type = %q %q %q", pp.ID(), pp.Name(), pp.Type())
	}
	if pp.Ceremony == nil {
		t.Fatal("Ceremony is nil")
	}
}

func TestBeginLogin_ReturnsChallenge(t *testing.T) {
	t.Parallel()
	p, err := New(Options{
		RPID:      "localhost",
		RPOrigins: []string{"http://localhost:3000"},
		Store:     NewMemoryStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*goauth.PasskeyProvider).Ceremony
	options, challengeID, err := c.BeginLogin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if options == nil || challengeID == "" {
		t.Fatalf("options=%v challenge=%q", options, challengeID)
	}
}

func TestMemoryStore_UserAndChallenge(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	s.SeedUser(User{ID: "u1", Name: "ada", DisplayName: "Ada"})
	u, err := s.GetUser(context.Background(), "u1")
	if err != nil || u == nil || u.Name != "ada" {
		t.Fatalf("GetUser = %#v err=%v", u, err)
	}
	handle := []byte("handle-1")
	if err := s.EnsureUserHandle(context.Background(), "u1", handle); err != nil {
		t.Fatal(err)
	}
	byHandle, err := s.GetUserByHandle(context.Background(), handle)
	if err != nil || byHandle == nil || byHandle.ID != "u1" {
		t.Fatalf("GetUserByHandle = %#v err=%v", byHandle, err)
	}
	if err := s.PutChallenge(context.Background(), "c1", []byte(`{"ok":true}`), challengeTTL); err != nil {
		t.Fatal(err)
	}
	raw, err := s.TakeChallenge(context.Background(), "c1")
	if err != nil || string(raw) != `{"ok":true}` {
		t.Fatalf("TakeChallenge = %q err=%v", raw, err)
	}
	raw, err = s.TakeChallenge(context.Background(), "c1")
	if err != nil || raw != nil {
		t.Fatalf("second take = %q err=%v", raw, err)
	}
}
