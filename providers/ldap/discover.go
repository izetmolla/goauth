package ldap

import (
	"fmt"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

func discoverBaseDN(conn *ldapv3.Conn) (string, error) {
	req := ldapv3.NewSearchRequest(
		"",
		ldapv3.ScopeBaseObject,
		ldapv3.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("%w: RootDSE: %v", ErrConnection, err)
	}
	if len(res.Entries) != 1 {
		return "", fmt.Errorf("%w: unexpected RootDSE response", ErrConnection)
	}
	baseDN := res.Entries[0].GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		return "", fmt.Errorf("%w: defaultNamingContext not found", ErrConnection)
	}
	return baseDN, nil
}
