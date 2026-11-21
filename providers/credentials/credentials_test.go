package credentials

import (
	"context"
	"net/http"
	"testing"

	"github.com/izetmolla/goauth"
)

func TestNew_Defaults(t *testing.T) {
	t.Parallel()
	p, ok := New(Options{
		Authorize: func(context.Context, map[string]string, *http.Request) (*goauth.OAuthUser, error) {
			return &goauth.OAuthUser{ID: "u1"}, nil
		},
	}).(*goauth.CredentialsProvider)
	if !ok {
		t.Fatalf("type = %T", New(Options{}))
	}
	if p.ID() != "credentials" {
		t.Fatalf("ID = %q", p.ID())
	}
	if p.Name() != "Credentials" {
		t.Fatalf("Name = %q", p.Name())
	}
	if p.Type() != goauth.ProviderCredentials {
		t.Fatalf("Type = %q", p.Type())
	}
	if p.Authorize == nil {
		t.Fatal("Authorize is nil")
	}
}

func TestNew_Overrides(t *testing.T) {
	t.Parallel()
	p := New(Options{
		ID:   "local",
		Name: "Local Login",
		Fields: []goauth.CredentialField{
			{Name: "email", Label: "Email", Type: "email"},
		},
		Authorize: func(context.Context, map[string]string, *http.Request) (*goauth.OAuthUser, error) {
			return nil, nil
		},
		Register: func(context.Context, map[string]string, *http.Request) (*goauth.OAuthUser, error) {
			return &goauth.OAuthUser{ID: "new"}, nil
		},
		RegisterFields: []goauth.CredentialField{
			{Name: "email", Label: "Email", Type: "email"},
			{Name: "password", Label: "Password", Type: "password"},
		},
	}).(*goauth.CredentialsProvider)
	if p.ID() != "local" || p.Name() != "Local Login" {
		t.Fatalf("id/name = %q / %q", p.ID(), p.Name())
	}
	if len(p.Fields) != 1 || p.Fields[0].Name != "email" {
		t.Fatalf("Fields = %#v", p.Fields)
	}
	if p.Register == nil || len(p.RegisterFields) != 2 {
		t.Fatalf("register not wired: %#v", p.RegisterFields)
	}
}

func TestAuthorizeWiring(t *testing.T) {
	t.Parallel()
	p := New(Options{
		Authorize: func(_ context.Context, creds map[string]string, _ *http.Request) (*goauth.OAuthUser, error) {
			if creds["email"] != "a@b.c" {
				t.Fatalf("creds = %#v", creds)
			}
			return &goauth.OAuthUser{ID: "u1", Email: creds["email"]}, nil
		},
	}).(*goauth.CredentialsProvider)
	u, err := p.Authorize(context.Background(), map[string]string{"email": "a@b.c"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "u1" || u.Email != "a@b.c" {
		t.Fatalf("got %#v", u)
	}
}
