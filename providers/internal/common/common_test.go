package common

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   any
		want string
	}{
		{"abc", "abc"},
		{float64(42), "42"},
		{float64(1.5), "1.5"},
		{int(7), "7"},
		{int64(9), "9"},
		{true, "true"},
		{false, "false"},
		{nil, ""},
		{struct{}{}, ""},
	}
	for _, tc := range cases {
		if got := String(tc.in); got != tc.want {
			t.Errorf("String(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	t.Parallel()
	if got := FirstNonEmpty("", "", "x", "y"); got != "x" {
		t.Fatalf("got %q", got)
	}
	if got := FirstNonEmpty("", ""); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestValues(t *testing.T) {
	t.Parallel()
	if Values(nil) != nil {
		t.Fatal("nil map should yield nil")
	}
	if Values(map[string]string{}) != nil {
		t.Fatal("empty map should yield nil")
	}
	got := Values(map[string]string{"a": "1"})
	if len(got["a"]) != 1 || got["a"][0] != "1" {
		t.Fatalf("got %#v", got)
	}
}

func TestMapAndNestedString(t *testing.T) {
	t.Parallel()
	if Map("nope") != nil {
		t.Fatal("expected nil")
	}
	m := map[string]any{
		"picture": map[string]any{
			"data": map[string]any{"url": "https://img.example/a.png"},
		},
	}
	if got := NestedString(m, "picture.data.url"); got != "https://img.example/a.png" {
		t.Fatalf("got %q", got)
	}
	if NestedString(m, "missing.path") != "" {
		t.Fatal("expected empty")
	}
	if NestedString(nil, "a.b") != "" {
		t.Fatal("expected empty for nil")
	}
}

func TestRawString(t *testing.T) {
	t.Parallel()
	if RawString(nil, "k") != "" {
		t.Fatal("nil raw")
	}
	if got := RawString(map[string]any{"k": float64(3)}, "k"); got != "3" {
		t.Fatalf("got %q", got)
	}
}

func TestDecodeIDTokenPayload(t *testing.T) {
	t.Parallel()
	claims := map[string]any{"sub": "user-1", "email": "a@b.c"}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	token := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	got, err := DecodeIDTokenPayload(token)
	if err != nil {
		t.Fatal(err)
	}
	if String(got["sub"]) != "user-1" || String(got["email"]) != "a@b.c" {
		t.Fatalf("got %#v", got)
	}
	if _, err := DecodeIDTokenPayload("not-a-jwt"); err == nil {
		t.Fatal("expected error")
	}
}

func TestMapUser(t *testing.T) {
	t.Parallel()
	f := MapUser(map[string]any{
		"sub":     "s1",
		"name":    "Ada",
		"email":   "ada@example.com",
		"picture": "https://img/ada",
	})
	if f.ID != "s1" || f.Name != "Ada" || f.Email != "ada@example.com" || f.Image != "https://img/ada" {
		t.Fatalf("got %#v", f)
	}
	f = MapUser(map[string]any{
		"id":         float64(99),
		"login":      "octocat",
		"avatar_url": "https://gh/avatar",
		"mail":       "octocat@github.com",
	})
	if f.ID != "99" || f.Name != "octocat" || f.Email != "octocat@github.com" || f.Image != "https://gh/avatar" {
		t.Fatalf("aliases %#v", f)
	}
	f = MapUser(nil)
	if f.ID != "" {
		t.Fatalf("nil profile %#v", f)
	}
}
