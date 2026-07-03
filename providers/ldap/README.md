# LDAP authentication

Small wrapper around [`github.com/go-ldap/ldap/v3`](https://github.com/go-ldap/ldap) for verifying usernames and passwords against an LDAP directory and reading profile attributes from the matched entry.

## How it works

1. Connect to the LDAP server.
2. Bind with a service account (optional) to run the user search.
3. Find exactly one entry under `BaseDN` using `UserFilter` (`%s` is replaced with an escaped username).
4. Bind as that entry with the supplied password.
5. On success, return a [`User`](user.go) with mapped fields (`Name`, `Email`, `Roles`, …) and all requested raw LDAP attributes.

## Quick start

```go
client, err := ldap.New(ldap.Config{
	URL:          "ldap://ldap.example.com:389",
	BindDN:       "cn=readonly,dc=example,dc=com",
	BindPassword: "service-account-password",
	BaseDN:       "ou=people,dc=example,dc=com",
	UserFilter:   "(uid=%s)",
	UserAttribute: "uid",
	EmailAttribute: "mail",
	NameAttributes: []string{"displayName", "cn"},
	RoleAttribute:  "memberOf", // Active Directory groups
})
if err != nil {
	log.Fatal(err)
}

user, err := client.Login("jdoe", "user-password")
if err != nil {
	// handle ErrInvalidCredentials, ErrUserNotFound, …
}

fmt.Println(user.Name)              // Jane Doe
fmt.Println(user.Email)             // jdoe@example.com
fmt.Println(user.Roles)             // []string{"Staff", "Editors"} (CNs from memberOf)
fmt.Println(user.Get("department")) // any extra attribute you listed in Config.Attributes
fmt.Println(user.Identity())        // username or DN
```

## User result

After a successful `Login`, you get:

| Field | Source |
|-------|--------|
| `DN` | Entry distinguished name |
| `Username` | `UsernameAttribute`, else `UserAttribute` |
| `Email` | `EmailAttribute` (default `mail`) |
| `Name` | First hit from `NameAttributes` (default `displayName`, then `cn`) |
| `Roles` | Values from `RoleAttribute`; when `RoleFromDN` is true, `CN=` is extracted (default for `memberOf`) |
| `Attributes` | Map of every attribute requested during search |

Helpers:

- `user.Get("title")` — first value for any fetched attribute
- `user.GetAll("memberOf")` — all values
- `user.Identity()` — `Username` if set, otherwise `DN`

## Configuration

| Field | Required | Description |
|-------|----------|-------------|
| `URL` | yes | `ldap://host:389` or `ldaps://host:636` |
| `BaseDN` | yes | Search base, e.g. `dc=example,dc=com` |
| `BindDN` | no | Service account DN for search |
| `BindPassword` | no | Password for `BindDN` |
| `UserFilter` | no | `printf` filter; `%s` = escaped username. Default: `(uid=%s)` |
| `UserAttribute` | no | Stored on `User.Username` (e.g. `uid`, `mail`) |
| `UsernameAttribute` | no | Overrides `UserAttribute` for `User.Username` |
| `EmailAttribute` | no | Default: `mail` |
| `NameAttributes` | no | Default: `displayName`, `cn` |
| `RoleAttribute` | no | Multi-valued attribute → `User.Roles` (e.g. `memberOf`) |
| `RoleFromDN` | no | Extract `CN=` from role values; default `true` when `RoleAttribute` is `memberOf` |
| `Attributes` | no | Extra LDAP attributes copied into `User.Attributes` |
| `InsecureSkipVerify` | no | Skip TLS verification (dev only). Env: `LDAP_INSECURE_SKIP_VERIFY=true` |
| `TLSServerName` | no | Verify cert against this hostname when connecting by IP. Env: `LDAP_TLS_SERVER_NAME` |
| `Timeout` | no | Default `10s` |

### No service account (direct bind) — only the server IP

When you **do not** have an LDAP admin / reader password, enable **direct bind**: each user signs in with their own AD password (email + password). No `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD`.

```env
LDAP_URL=ldaps://192.168.11.61:636
LDAP_INSECURE_SKIP_VERIFY=true
LDAP_DIRECT_BIND=true
LDAP_USER_BIND_DN=%s
LDAP_BASE_DN=DC=uet,DC=com
LDAP_USER_FILTER=(&(objectClass=user)(|(mail=%s)(userPrincipalName=%s)))
```

Sign in with **`user@uet.com`** and that user’s AD password.

If users log in with short names (`jdoe`), set:

```env
LDAP_DOMAIN=uet.com
# or: LDAP_USER_BIND_DN=%s@uet.com
```

After a successful bind, the app loads `displayName`, `mail`, `memberOf`, etc. when AD allows the user to read their own entry.

### Active Directory service bind (error 49 / data 52e)

`LDAP Result Code 49` with `data 52e` on **service bind** means Active Directory rejected `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` — wrong password, wrong account name, or the DN does not exist.

`CN=admin,DC=uet,DC=com` is often wrong on AD. Use one of these bind identities instead (with the real password):

```env
LDAP_BIND_DN=Administrator@uet.com
# or
LDAP_BIND_DN=UET\Administrator
# or (full DN — find yours in AD Users and Computers)
LDAP_BIND_DN=CN=Administrator,CN=Users,DC=uet,DC=com
```

Test from a machine that can reach the DC:

```bash
ldapsearch -H ldaps://192.168.11.61:636 -x \
  -D "Administrator@uet.com" -w 'YOUR_PASSWORD' \
  -b "DC=uet,DC=com" -s base "(objectClass=*)" defaultNamingContext
```

When that works, use the same `-D` value as `LDAP_BIND_DN` and `-w` as `LDAP_BIND_PASSWORD`.

### TLS when using an IP address (`ldaps://192.168.x.x`)

Go requires the server certificate to list that IP in **Subject Alternative Names**. If it does not:

- **Development:** `LDAP_INSECURE_SKIP_VERIFY=true`
- **Production:** use the hostname on the cert in `LDAP_URL`, or keep the IP and set `LDAP_TLS_SERVER_NAME` to that hostname (e.g. `ldap.uet.com`)

## Examples

### Sign in by email with profile + groups (OpenLDAP / AD)

```go
client, err := ldap.New(ldap.Config{
	URL:            "ldap://ldap.example.com:389",
	BindDN:         "cn=readonly,dc=example,dc=com",
	BindPassword:   os.Getenv("LDAP_BIND_PASSWORD"),
	BaseDN:         "ou=users,dc=example,dc=com",
	UserFilter:     "(&(objectClass=inetOrgPerson)(mail=%s))",
	UserAttribute:  "mail",
	NameAttributes: []string{"displayName", "cn"},
	RoleAttribute:  "memberOf",
	Attributes:     []string{"title", "department", "telephoneNumber"},
})

user, err := client.Login(req.Email, req.Password)
if err != nil {
	return err
}

// Map into your app user / JWT roles
localUser, err := db.FindOrCreateByEmail(user.Email)
localUser.DisplayName = user.Name
localUser.Roles = mergeRoles(localUser.Roles, user.Roles)
```

### Active Directory roles from security groups

```go
roleFromDN := true
client, err := ldap.New(ldap.Config{
	URL:            "ldaps://ad.example.com:636",
	BindDN:         "CN=LDAP Reader,OU=Service Accounts,DC=example,DC=com",
	BindPassword:   os.Getenv("LDAP_BIND_PASSWORD"),
	BaseDN:         "DC=example,DC=com",
	UserFilter:     "(&(objectClass=user)(userPrincipalName=%s))",
	UserAttribute:  "userPrincipalName",
	EmailAttribute: "mail",
	NameAttributes: []string{"displayName", "cn"},
	RoleAttribute:  "memberOf",
	RoleFromDN:     &roleFromDN,
	Attributes:     []string{"sAMAccountName", "department", "title"},
})

user, err := client.Login("user@example.com", password)
// user.Roles => []string{"Domain Users", "App-Admins", ...}
```

### Custom roles attribute (not DN-based)

Some directories expose a plain role name attribute instead of `memberOf`:

```go
roleFromDN := false
client, err := ldap.New(ldap.Config{
	// ...
	RoleAttribute: "eduPersonAffiliation", // e.g. "staff", "student"
	RoleFromDN:    &roleFromDN,
})
```

### Read any fetched attribute

```go
user, err := client.Login(username, password)
if err != nil {
	return err
}

department := user.Get("department")
groups := user.GetAll("memberOf") // raw DNs when RoleFromDN is false
for name, values := range user.Attributes {
	log.Printf("%s: %v", name, values)
}
```

### Handling errors

```go
user, err := client.Login(username, password)
switch {
case err == nil:
	// use user.Name, user.Email, user.Roles, user.Attributes
case errors.Is(err, ldap.ErrUserNotFound):
case errors.Is(err, ldap.ErrInvalidCredentials):
case errors.Is(err, ldap.ErrAmbiguousUser):
case errors.Is(err, ldap.ErrConnection):
default:
}
```

### Wiring into the authorization package

LDAP validates credentials and supplies directory metadata; sessions and JWTs stay in goauth. The simplest integration is through the [credentials provider](../credentials/README.md)'s `Authorize` function:

1. `user, err := client.Login(email, password)`
2. Find or provision the app user from `user.Email` / `user.Username`
3. Optionally sync `user.Roles` into your user record or JWT `roles` claim
4. Return the user (goauth creates the session and signs the token pair), or issue tokens manually with `auth.Authorize(...)`

## Errors

| Variable | When |
|----------|------|
| `ErrInvalidConfig` | Missing `URL` or `BaseDN` in `New` |
| `ErrInvalidCredentials` | Empty username/password or user bind failed |
| `ErrUserNotFound` | Search returned no entries |
| `ErrAmbiguousUser` | Search returned more than one entry |
| `ErrConnection` | Dial, service bind, or search failed |

## User filter notes

- Always use `%s` for the username placeholder; it is passed through `ldap.EscapeFilter`.
- Request only attributes you need via `Attributes` and the mapping fields — LDAP returns what you ask for.
- For AD, `memberOf` often requires the service account to have permission to read group membership.
- If `Roles` is empty, set `RoleAttribute` and ensure that attribute is returned for your users (or add it to `Attributes` and map manually with `user.GetAll`).
