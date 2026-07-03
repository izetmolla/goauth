package ldap

import "testing"

func TestFormatUserFilter_multiplePlaceholders(t *testing.T) {
	tpl := "(&(objectClass=user)(|(mail=%s)(userPrincipalName=%s)))"
	got := formatUserFilter(tpl, "a@b.com")
	want := "(&(objectClass=user)(|(mail=a@b.com)(userPrincipalName=a@b.com)))"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestConfig_directBindDefaults(t *testing.T) {
	c, err := New(Config{
		URL:        "ldap://localhost:389",
		DirectBind: true,
		Domain:     "uet.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.UserFilter != "(&(objectClass=user)(userPrincipalName=%s))" {
		t.Fatalf("UserFilter: got %q", c.cfg.UserFilter)
	}
	if got := c.userBindIdentity("student"); got != "student@uet.com" {
		t.Fatalf("UPN: got %q", got)
	}
}
