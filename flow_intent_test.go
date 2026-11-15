package goauth

import (
	"strings"
	"testing"
)

func TestConnectIntentRoundTrip(t *testing.T) {
	const secret = "test-secret"
	in := connectIntent{UserID: "u1", SessionID: "s1", ResourceID: "r1"}
	value, err := in.encode(secret)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, ok := decodeConnectIntent(value, secret)
	if !ok || got != in {
		t.Fatalf("decode = %+v, %v; want %+v, true", got, ok, in)
	}
}

func TestConnectIntentRejectsTampering(t *testing.T) {
	const secret = "test-secret"
	value, err := connectIntent{UserID: "u1", SessionID: "s1", ResourceID: "r1"}.encode(secret)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	sig := value[strings.LastIndex(value, "|")+1:]

	tests := map[string]string{
		"wrong secret":       mustEncode(t, connectIntent{UserID: "u1", SessionID: "s1", ResourceID: "r1"}, "other"),
		"swapped user":       "connect|attacker|s1|r1|" + sig,
		"swapped resource":   "connect|u1|s1|victim-resource|" + sig,
		"legacy intent only": "connect|" + signValue("connect", secret),
		"missing user":       mustEncode(t, connectIntent{SessionID: "s1"}, secret),
		"missing session":    mustEncode(t, connectIntent{UserID: "u1"}, secret),
		"wrong intent":       strings.Replace(value, "connect|", "signin|", 1),
		"empty":              "",
	}
	for name, v := range tests {
		t.Run(name, func(t *testing.T) {
			if _, ok := decodeConnectIntent(v, secret); ok {
				t.Fatalf("decodeConnectIntent(%q) accepted a tampered value", v)
			}
		})
	}
}

func TestConnectIntentRejectsSeparatorInIDs(t *testing.T) {
	if _, err := (connectIntent{UserID: "u1|x", SessionID: "s1"}).encode("s"); err == nil {
		t.Fatal("encode accepted an id containing '|'")
	}
}

func TestValidateConnectResourceID(t *testing.T) {
	if id, err := validateConnectResourceID("  "); err != nil || id != "" {
		t.Fatalf("blank id = %q, %v; want \"\", nil", id, err)
	}
	if _, err := validateConnectResourceID("not-a-uuid"); err == nil {
		t.Fatal("accepted a non-uuid resource id")
	}
	const id = "7d3c5c8e-2a0e-4c55-9f43-5d9a8a2b7f10"
	if got, err := validateConnectResourceID(" " + id + " "); err != nil || got != id {
		t.Fatalf("got %q, %v; want %q, nil", got, err, id)
	}
}

func mustEncode(t *testing.T, c connectIntent, secret string) string {
	t.Helper()
	v, err := c.encode(secret)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return v
}
