package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

var (
	ErrInvalidConfig      = errors.New("invalid ldap config")
	ErrInvalidCredentials = errors.New("invalid ldap credentials")
	ErrUserNotFound       = errors.New("ldap user not found")
	ErrAmbiguousUser      = errors.New("ldap user search returned multiple entries")
	ErrConnection         = errors.New("ldap connection failed")
)

// Config holds connection and search settings for the LDAP server.
type Config struct {
	// URL is the LDAP server address, e.g. ldap://host:389 or ldaps://host:636.
	URL string
	// BindDN and BindPassword are used to search for the user (service account).
	// Leave both empty when using DirectBind (user binds with their own password).
	BindDN       string
	BindPassword string
	// DirectBind authenticates by binding as the user (no service account).
	// Typical for Active Directory: set UserBindDN to "%s" and sign in with user@domain.com.
	DirectBind bool
	// UserBindDN is a printf template for the bind identity; %s is the login username.
	// Examples: "%s" (UPN/email as typed), "%s@uet.com", "UET\\%s".
	UserBindDN string
	// Domain appends @domain to usernames without @ (e.g. student → student@uet.com).
	Domain string
	// BaseDN is the search base, e.g. dc=example,dc=com.
	// Leave empty with DirectBind to read defaultNamingContext from RootDSE.
	BaseDN string
	// UserFilter is a printf-style filter; %s is replaced with the escaped username.
	// Defaults to "(uid=%s)" when empty.
	UserFilter string
	// UserAttribute is fetched and stored on User.Username (e.g. mail, uid, sAMAccountName).
	UserAttribute string
	// UsernameAttribute overrides UserAttribute for User.Username when set.
	UsernameAttribute string
	// EmailAttribute maps to User.Email (default: mail).
	EmailAttribute string
	// NameAttributes are tried in order for User.Name (default: displayName, cn).
	NameAttributes []string
	// RoleAttribute is a multi-valued LDAP attribute mapped to User.Roles
	// (e.g. memberOf for Active Directory).
	RoleAttribute string
	// RoleFromDN extracts CN= from each role value (typical for memberOf).
	// Defaults to true when RoleAttribute is "memberOf".
	RoleFromDN *bool
	// Attributes lists extra LDAP attributes to fetch into User.Attributes.
	Attributes []string
	// InsecureSkipVerify disables TLS certificate verification for ldaps URLs.
	InsecureSkipVerify bool
	// TLSServerName sets the TLS ServerName when the URL host is an IP (or otherwise
	// differs from the name on the server certificate). Use the hostname from the cert SAN.
	TLSServerName string
	// Timeout applies to dial, bind, and search operations.
	Timeout time.Duration
}

// Client authenticates users against an LDAP directory.
type Client struct {
	cfg    Config
	baseDN string // cached after RootDSE discovery
}

// New validates cfg and returns a ready-to-use Client.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("%w: URL is required", ErrInvalidConfig)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if strings.TrimSpace(cfg.BaseDN) == "" && !cfg.directBindEnabled() {
		return nil, fmt.Errorf("%w: BaseDN is required unless DirectBind is enabled", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.UserFilter) == "" {
		if cfg.directBindEnabled() {
			cfg.UserFilter = "(&(objectClass=user)(userPrincipalName=%s))"
		} else {
			cfg.UserFilter = "(uid=%s)"
		}
	}
	if cfg.directBindEnabled() {
		cfg.applyDirectBindDefaults()
	}
	if strings.TrimSpace(cfg.BindDN) != "" && cfg.BindPassword == "" {
		return nil, fmt.Errorf("%w: BindPassword is required when BindDN is set", ErrInvalidConfig)
	}
	if cfg.directBindEnabled() && strings.TrimSpace(cfg.UserBindDN) == "" && strings.TrimSpace(cfg.Domain) == "" {
		cfg.UserBindDN = "%s"
	}
	if cfg.directBindEnabled() && strings.TrimSpace(cfg.BindDN) != "" {
		return nil, fmt.Errorf("%w: DirectBind cannot be used together with BindDN", ErrInvalidConfig)
	}
	return &Client{cfg: cfg}, nil
}

func (cfg Config) directBindEnabled() bool {
	return cfg.DirectBind || (strings.TrimSpace(cfg.BindDN) == "" && strings.TrimSpace(cfg.UserBindDN) != "")
}

// Login verifies username and password against ldapv3.
// On success it returns the matched entry as a User with mapped and raw attributes.
func (c *Client) Login(username, password string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if c.cfg.directBindEnabled() {
		return c.loginDirect(conn, username, password)
	}

	if c.cfg.BindDN != "" {
		if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
			return nil, serviceBindError(err)
		}
	}

	entry, err := c.searchUser(conn, username)
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(entry.DN, password); err != nil {
		var ldapErr *ldapv3.Error
		if errors.As(err, &ldapErr) && (ldapErr.ResultCode == ldapv3.LDAPResultInvalidCredentials ||
			ldapErr.ResultCode == ldapv3.LDAPResultInvalidDNSyntax) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("%w: user bind: %v", ErrInvalidCredentials, err)
	}

	return userFromEntry(entry, c.cfg), nil
}

// GetDomain returns the domain of the LDAP server.
func (c *Client) GetDomain() string {
	return c.cfg.Domain
}

func (c *Client) UsernameWithDomain(username string) string {
	if !strings.Contains(username, "@") {
		return fmt.Sprintf("%s@%s", username, c.cfg.Domain)
	}
	return username
}

// loginDirect binds as the user (no service account), then loads their LDAP entry.
func (c *Client) loginDirect(conn *ldapv3.Conn, username, password string) (*User, error) {
	bindIdentity := c.userBindIdentity(username)
	if err := conn.Bind(bindIdentity, password); err != nil {
		var ldapErr *ldapv3.Error
		if errors.As(err, &ldapErr) && (ldapErr.ResultCode == ldapv3.LDAPResultInvalidCredentials ||
			ldapErr.ResultCode == ldapv3.LDAPResultInvalidDNSyntax) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("%w: user bind: %v", ErrInvalidCredentials, err)
	}

	entry, err := c.searchUser(conn, bindIdentity)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return userFromBindIdentity(username, bindIdentity), nil
		}
		return nil, err
	}
	return userFromEntry(entry, c.cfg), nil
}

func (c *Client) userBindIdentity(username string) string {
	if strings.Contains(username, "@") {
		return username
	}
	if tpl := strings.TrimSpace(c.cfg.UserBindDN); tpl != "" {
		return fmt.Sprintf(tpl, username)
	}
	if domain := strings.TrimSpace(c.cfg.Domain); domain != "" {
		return username + "@" + strings.TrimPrefix(domain, "@")
	}
	return username
}

func (cfg *Config) applyDirectBindDefaults() {
	if strings.TrimSpace(cfg.UserAttribute) == "" {
		cfg.UserAttribute = "sAMAccountName"
	}
	if len(cfg.Attributes) == 0 {
		cfg.Attributes = []string{"givenName", "sn", "mail", "sAMAccountName", "userPrincipalName"}
	}
	if len(cfg.NameAttributes) == 0 {
		cfg.NameAttributes = []string{"displayName", "cn", "givenName"}
	}
}

func (c *Client) resolveBaseDN(conn *ldapv3.Conn) (string, error) {
	if dn := strings.TrimSpace(c.cfg.BaseDN); dn != "" {
		return dn, nil
	}
	if c.baseDN != "" {
		return c.baseDN, nil
	}
	dn, err := discoverBaseDN(conn)
	if err != nil {
		return "", err
	}
	c.baseDN = dn
	return dn, nil
}

func userFromBindIdentity(username, bindIdentity string) *User {
	u := &User{
		DN:         bindIdentity,
		Username:   username,
		Attributes: map[string][]string{},
	}
	if strings.Contains(username, "@") {
		u.Email = username
	}
	return u
}

func formatUserFilter(tpl, username string) string {
	escaped := ldapv3.EscapeFilter(username)
	n := strings.Count(tpl, "%s")
	if n == 0 {
		return tpl
	}
	args := make([]any, n)
	for i := range args {
		args[i] = escaped
	}
	return fmt.Sprintf(tpl, args...)
}

func (c *Client) searchUser(conn *ldapv3.Conn, searchTerm string) (*ldapv3.Entry, error) {
	baseDN, err := c.resolveBaseDN(conn)
	if err != nil {
		return nil, err
	}
	filter := formatUserFilter(c.cfg.UserFilter, searchTerm)
	search := ldapv3.NewSearchRequest(
		baseDN,
		ldapv3.ScopeWholeSubtree,
		ldapv3.NeverDerefAliases,
		1,
		int(c.cfg.Timeout.Seconds()),
		false,
		filter,
		c.searchAttributes(),
		nil,
	)

	result, err := conn.Search(search)
	if err != nil {
		return nil, fmt.Errorf("%w: search: %v", ErrConnection, err)
	}
	switch len(result.Entries) {
	case 0:
		return nil, ErrUserNotFound
	case 1:
		return result.Entries[0], nil
	default:
		return nil, ErrAmbiguousUser
	}
}

func serviceBindError(err error) error {
	var ldapErr *ldapv3.Error
	if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldapv3.LDAPResultInvalidCredentials {
		msg := "check LDAP_BIND_DN and LDAP_BIND_PASSWORD"
		if strings.Contains(strings.ToLower(err.Error()), "52e") {
			msg = "Active Directory rejected the bind (52e: wrong bind identity or password)"
		}
		return fmt.Errorf("%w: service bind: %s: %v", ErrConnection, msg, err)
	}
	return fmt.Errorf("%w: service bind: %v", ErrConnection, err)
}

func (c *Client) dial() (*ldapv3.Conn, error) {
	opts := []ldapv3.DialOpt{ldapv3.DialWithDialer(&net.Dialer{Timeout: c.cfg.Timeout})}
	if tlsCfg := c.tlsConfig(); tlsCfg != nil {
		opts = append(opts, ldapv3.DialWithTLSConfig(tlsCfg))
	}

	conn, err := ldapv3.DialURL(c.cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnection, err)
	}
	conn.SetTimeout(c.cfg.Timeout)
	return conn, nil
}

func (c *Client) tlsConfig() *tls.Config {
	sn := strings.TrimSpace(c.cfg.TLSServerName)
	if !c.cfg.InsecureSkipVerify && sn == "" {
		return nil
	}
	return &tls.Config{
		ServerName:         sn,
		InsecureSkipVerify: c.cfg.InsecureSkipVerify,
	}
}

func (c *Client) searchAttributes() []string {
	seen := make(map[string]struct{})
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
	}

	add("dn")
	add(c.cfg.UserAttribute)
	add(c.cfg.UsernameAttribute)
	add(firstNonEmpty(c.cfg.EmailAttribute, "mail"))
	for _, attr := range c.cfg.NameAttributes {
		add(attr)
	}
	if len(c.cfg.NameAttributes) == 0 {
		add("displayName")
		add("cn")
	}
	add(c.cfg.RoleAttribute)
	for _, attr := range c.cfg.Attributes {
		add(attr)
	}

	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	return out
}

func (cfg Config) roleFromDN() bool {
	if cfg.RoleFromDN != nil {
		return *cfg.RoleFromDN
	}
	return strings.EqualFold(strings.TrimSpace(cfg.RoleAttribute), "memberOf")
}

func (c *Client) GetConfig() Config {
	return c.cfg
}
