package ldap

import (
	"strings"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

// User is the authenticated directory entry returned by Login.
type User struct {
	// DN is the user's distinguished name.
	DN string
	// Attributes holds every LDAP attribute fetched during search (lowercase names).
	Attributes map[string][]string

	// Username is populated from Config.UsernameAttribute or Config.UserAttribute.
	Username string
	// Email from Config.EmailAttribute (default: mail).
	Email string
	// Name from the first non-empty Config.NameAttributes value.
	Name string
	// Roles from Config.RoleAttribute (e.g. memberOf group DNs or plain role values).
	Roles []string
}

// LoginEmail returns the best email/UPN to look up the app user after LDAP auth.
func (u *User) LoginEmail(fallback string) string {
	if u == nil {
		return fallback
	}
	for _, v := range []string{u.Email, u.Get("mail"), u.Get("userPrincipalName"), u.Username} {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return fallback
}

// Identity returns Username when set, otherwise DN.
func (u *User) Identity() string {
	if u == nil {
		return ""
	}
	if u.Username != "" {
		return u.Username
	}
	return u.DN
}

// Get returns the first value for an LDAP attribute (case-insensitive).
func (u *User) Get(attr string) string {
	if u == nil {
		return ""
	}
	for k, vals := range u.Attributes {
		if strings.EqualFold(k, attr) && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// GetAll returns all values for an LDAP attribute (case-insensitive).
func (u *User) GetAll(attr string) []string {
	if u == nil {
		return nil
	}
	for k, vals := range u.Attributes {
		if strings.EqualFold(k, attr) {
			out := make([]string, len(vals))
			copy(out, vals)
			return out
		}
	}
	return nil
}

func userFromEntry(entry *ldapv3.Entry, cfg Config) *User {
	if entry == nil {
		return nil
	}

	u := &User{
		DN:         entry.DN,
		Attributes: copyEntryAttributes(entry),
	}

	usernameAttr := firstNonEmpty(cfg.UsernameAttribute, cfg.UserAttribute)
	if usernameAttr != "" {
		u.Username = entry.GetAttributeValue(usernameAttr)
	}

	emailAttr := firstNonEmpty(cfg.EmailAttribute, "mail")
	u.Email = entry.GetAttributeValue(emailAttr)

	nameAttrs := cfg.NameAttributes
	if len(nameAttrs) == 0 {
		nameAttrs = []string{"displayName", "cn"}
	}
	for _, attr := range nameAttrs {
		if v := entry.GetAttributeValue(attr); v != "" {
			u.Name = v
			break
		}
	}
	if u.Name == "" {
		gn := entry.GetAttributeValue("givenName")
		sn := entry.GetAttributeValue("sn")
		u.Name = strings.TrimSpace(gn + " " + sn)
	}
	if u.Username == "" {
		u.Username = entry.GetAttributeValue("sAMAccountName")
	}
	if u.Email == "" {
		u.Email = entry.GetAttributeValue("userPrincipalName")
	}

	if roleAttr := strings.TrimSpace(cfg.RoleAttribute); roleAttr != "" {
		raw := entry.GetAttributeValues(roleAttr)
		if cfg.roleFromDN() {
			u.Roles = cnFromDNs(raw)
		} else {
			u.Roles = append([]string(nil), raw...)
		}
	}

	return u
}

func copyEntryAttributes(entry *ldapv3.Entry) map[string][]string {
	attrs := entry.Attributes
	m := make(map[string][]string, len(attrs))
	for _, a := range attrs {
		if a == nil {
			continue
		}
		m[a.Name] = append([]string(nil), a.Values...)
	}
	return m
}

// cnFromDNs extracts the CN value from each DN, e.g.
// "CN=Admins,OU=Groups,DC=example,DC=com" -> "Admins".
func cnFromDNs(dns []string) []string {
	out := make([]string, 0, len(dns))
	for _, dn := range dns {
		if cn := cnFromDN(dn); cn != "" {
			out = append(out, cn)
		}
	}
	return out
}

func cnFromDN(dn string) string {
	for part := range strings.SplitSeq(dn, ",") {
		part = strings.TrimSpace(part)
		if len(part) > 3 && strings.EqualFold(part[:3], "CN=") {
			return part[3:]
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
