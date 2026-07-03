package ldap

import (
	"os"
	"testing"
)

// Run against a live directory:
//
//	LDAP_INTEGRATION=1 go test ./ldap/... -run TestIntegration -v
func TestIntegration_studentLogin(t *testing.T) {
	if os.Getenv("LDAP_INTEGRATION") == "" {
		t.Skip("set LDAP_INTEGRATION=1 to run")
	}

	url := envOr("LDAP_URL", "ldap://192.168.11.61:389")
	domain := envOr("LDAP_DOMAIN", "uet.com")
	user := envOr("LDAP_TEST_USER", "student")
	pass := envOr("LDAP_TEST_PASSWORD", "student")

	client, err := New(Config{
		URL:        url,
		DirectBind: true,
		Domain:     domain,
	})
	if err != nil {
		t.Fatal(err)
	}

	u, err := client.Login(user, pass)
	if err != nil {
		t.Fatalf("Login(%q): %v", user, err)
	}
	if u.DN == "" {
		t.Fatal("expected non-empty DN")
	}
	t.Logf("DN=%s", u.DN)
	t.Logf("Username=%s Email=%s Name=%q", u.Username, u.Email, u.Name)
	t.Logf("UPN=%s", u.Get("userPrincipalName"))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
