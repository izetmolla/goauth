---
title: LDAP / Active Directory
description: Verify passwords against LDAP or Active Directory, map groups to roles and issue goauth sessions.
---

# LDAP / Active Directory

The `providers/ldap` package verifies a username and password against a directory and returns the user's attributes and groups. Combine it with `auth.Authorize` to issue goauth sessions.

```go
import "github.com/izetmolla/goauth/providers/ldap"
```

## How login works

1. Connect to the server (`ldap://` or `ldaps://`).
2. Optionally bind with a service account to search.
3. Find exactly one entry under `BaseDN` matching `UserFilter`.
4. Bind as that entry with the user's password.
5. Return a `*ldap.User` with mapped fields and raw attributes.

## OpenLDAP with a service account

```go
client, err := ldap.New(ldap.Config{
	URL:            "ldaps://ldap.example.com:636",
	BindDN:         "cn=readonly,dc=example,dc=com",
	BindPassword:   os.Getenv("LDAP_BIND_PASSWORD"),
	BaseDN:         "ou=people,dc=example,dc=com",
	UserFilter:     "(uid=%s)",
	UserAttribute:  "uid",
	EmailAttribute: "mail",
	NameAttributes: []string{"displayName", "cn"},
	RoleAttribute:  "memberOf",
	Attributes:     []string{"department", "title"},
	Timeout:        10 * time.Second,
})
if err != nil {
	log.Fatal(err)
}

user, err := client.Login("jdoe", "their-password")
switch {
case errors.Is(err, ldap.ErrInvalidCredentials):
	// wrong password
case errors.Is(err, ldap.ErrUserNotFound):
	// no such user
case err != nil:
	// connection or configuration problem
}

fmt.Println(user.Name, user.Email, user.Roles) // Jane Doe jdoe@example.com [Staff Editors]
fmt.Println(user.Get("department"))
```

## Active Directory without a service account (direct bind)

Users bind with their own credentials; no reader account is needed:

```go
client, err := ldap.New(ldap.Config{
	URL:           "ldaps://dc01.corp.example.com:636",
	DirectBind:    true,
	UserBindDN:    "%s",          // bind as what the user typed (UPN / email)
	Domain:        "corp.example.com", // "jdoe" becomes "jdoe@corp.example.com"
	UserFilter:    "(&(objectClass=user)(|(mail=%s)(userPrincipalName=%s)))",
	RoleAttribute: "memberOf",
	// BaseDN empty: read defaultNamingContext from the RootDSE
})
```

Other `UserBindDN` forms: `"%s@corp.example.com"`, or `"CORP\\%s"` for down-level logon names.

## Configuration reference

| Field | Description |
|---|---|
| `URL` | `ldap://host:389` or `ldaps://host:636` (required) |
| `BindDN`, `BindPassword` | Service account for searching; leave empty with `DirectBind` |
| `DirectBind` | Bind as the user instead of searching first |
| `UserBindDN` | Printf template for the bind identity with `DirectBind` |
| `Domain` | Appended as `@domain` to usernames without `@` |
| `BaseDN` | Search base; may be empty with `DirectBind` |
| `UserFilter` | Printf filter, `%s` is the escaped username; default `(uid=%s)` |
| `UserAttribute`, `UsernameAttribute` | Source of `User.Username` |
| `EmailAttribute` | Source of `User.Email`; default `mail` |
| `NameAttributes` | Tried in order for `User.Name`; default `displayName`, `cn` |
| `RoleAttribute` | Multi-valued attribute for `User.Roles`, for example `memberOf` |
| `RoleFromDN` | Keep only the `CN=` part of each role value; default `true` for `memberOf` |
| `Attributes` | Extra attributes copied into `User.Attributes` |
| `InsecureSkipVerify` | Skip TLS verification (development only) |
| `TLSServerName` | Certificate name to verify when `URL` uses an IP address |
| `Timeout` | Dial, bind and search timeout; default `10s` |

Errors: `ldap.ErrInvalidConfig`, `ErrInvalidCredentials`, `ErrUserNotFound`, `ErrAmbiguousUser`, `ErrConnection`.

## Issuing a goauth session after LDAP login

Sync the directory user into your users table (so goauth can read its roles), then call `Authorize`:

```go
func ldapLogin(dir *ldap.Client, db *gorm.DB, auth *goauth.Authorization) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Username, Password string }
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		du, err := dir.Login(in.Username, in.Password)
		if errors.Is(err, ldap.ErrInvalidCredentials) || errors.Is(err, ldap.ErrUserNotFound) {
			http.Error(w, "invalid username or password", http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, "directory unavailable", http.StatusBadGateway)
			return
		}

		userID, err := upsertDirectoryUser(r.Context(), db, du)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		opts := append([]goauth.AuthorizeOptionsFunc{auth.WithUserID(userID)},
			auth.SessionMetaFromRequest(r, "ldap")...)
		tokens, sessionID, err := auth.Authorize(opts...)
		if err != nil {
			http.Error(w, "could not create session", http.StatusInternalServerError)
			return
		}
		auth.SetSessionIDCookie(w, r, sessionID)
		json.NewEncoder(w).Encode(map[string]any{
			"session_id": sessionID, "user_id": userID, "tokens": tokens,
		})
	}
}

// groupRoles maps directory groups to goauth role grants.
var groupRoles = map[string]string{
	"Domain Admins": "admin:rw",
	"HR":            "hr:rw",
	"Staff":         "user:r",
}

func upsertDirectoryUser(ctx context.Context, db *gorm.DB, du *ldap.User) (string, error) {
	roles := goauth.JSONBArray{}
	for _, g := range du.Roles {
		if grant, ok := groupRoles[g]; ok {
			roles = append(roles, grant)
		}
	}
	email := strings.ToLower(du.LoginEmail(du.Identity()))

	var id string
	err := db.WithContext(ctx).Raw(`
		INSERT INTO users (email, name, roles) VALUES (?, ?, ?)
		ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name, roles = EXCLUDED.roles
		RETURNING id`, email, du.Name, roles).Scan(&id).Error
	return id, err
}
```

Each sign-in re-syncs the groups, so directory changes reach goauth at the next sign-in. Roles are re-read from the users table on every token refresh.

## TLS with an IP address

Go verifies that the certificate covers the host in `URL`. If you connect by IP and the certificate only lists a hostname:

- **Production**: use the hostname in `URL`, or set `TLSServerName: "dc01.corp.example.com"`.
- **Development only**: `InsecureSkipVerify: true`.

## Testing the connection

```bash
ldapsearch -H ldaps://dc01.corp.example.com:636 -x \
  -D "jdoe@corp.example.com" -W \
  -b "DC=corp,DC=example,DC=com" "(userPrincipalName=jdoe@corp.example.com)" memberOf
```

`LDAP Result Code 49` with `data 52e` means Active Directory rejected the bind credentials.
