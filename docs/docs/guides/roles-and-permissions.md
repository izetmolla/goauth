---
title: Roles and permissions
description: Role grants with read/write permissions, route gates with WithRoles, and fine-grained checks with GetRole.
---

# Roles and permissions

## Role grants

A user's roles are a JSON array in the `roles` column of your users table. Each entry is a **grant**:

```text
name[:perms]
```

| Grant | Meaning |
|---|---|
| `admin:rw` | role `admin`, read and write |
| `hr:r` | role `hr`, read only |
| `finance:w` | role `finance`, write only |
| `editor` | role `editor`, no read/write flags |

Role names are matched case-insensitively. Spaces around values are trimmed.

```sql
UPDATE users SET roles = '["admin:rw", "hr:r"]' WHERE email = 'jane@example.com';
```

Roles are copied into every access token and re-read from the database whenever a token is issued or refreshed.

## Gate a route by role

`WithRoles` takes plain role **names**. The user needs at least one of them, whatever its perms:

```go
hrOrAdmin := auth.UseAPIAuthorization(auth.WithRoles([]string{"hr", "admin"}))
mux.Handle("GET /api/employees", hrOrAdmin(listEmployees))
```

| User grants | `WithRoles([]string{"hr", "admin"})` |
|---|---|
| `["hr:r"]` | allowed |
| `["admin:rw"]` | allowed |
| `["finance:rw"]` | `403` |
| `[]` or no `roles` claim | `403` |

The same option works with `UseWEBAuthorization`.

## Read vs. write with `GetRole`

`GetRole` tells you whether the user has the role, and which perms the matching grants include:

```go
hasRole, canRead, canWrite := auth.GetRole(endpointRoles, userRoles)
```

A typical pattern allows readers to `GET` and writers to change data:

```go
func requirePerm(auth *goauth.Authorization, role string) goauth.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			roles, _ := auth.GetRoles(r)
			has, canRead, canWrite := auth.GetRole([]string{role}, roles)

			readOnly := r.Method == http.MethodGet || r.Method == http.MethodHead
			switch {
			case !has:
				http.Error(w, "forbidden", http.StatusForbidden)
			case readOnly && !canRead:
				http.Error(w, "read access required", http.StatusForbidden)
			case !readOnly && !canWrite:
				http.Error(w, "write access required", http.StatusForbidden)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
}

mux.Handle("/api/payroll/", auth.UseAPIAuthorization()(requirePerm(auth, "hr")(payroll)))
```

| User grant | `GET /api/payroll` | `POST /api/payroll` |
|---|---|---|
| `hr:r` | 200 | 403 |
| `hr:rw` | 200 | 200 |
| `hr:w` | 403 | 200 |
| `admin:rw` | 403 | 403 |

When several grants match (for example `["hr:r", "HR:w"]`), the permissions are combined.

## Reading roles

```go
roles, err := auth.GetRoles(r)               // API: from the access token
data, err := auth.GetAuthDataWEB(r, r.Context()) // WEB: data.Roles from the database
```

`GetRoles` accepts the roles claim as a JSON array, a `[]string`, a JSON-encoded string such as `"[\"admin:rw\"]"`, or a single grant string.

`goauth.FormatRoles(goauth.JSONBArray{...})` converts a database value into `[]string`, dropping blanks and non-string entries.

## Changing roles

1. Update the `roles` column.
2. Cookie-based pages see the change on the next request (if Redis is enabled, as soon as the session is read from the database again).
3. API clients see it after their next token refresh, at most `AccessTokenDuration` later.

To remove access **immediately**, also sign the user out by marking their sessions deleted. See [Sign-out](./sign-out.md#sign-out-everywhere).

## Designing roles

- Use a few coarse roles (`admin`, `hr`, `finance`, `support`) and put read/write on the grant, rather than creating `hr-read` and `hr-write` roles.
- Keep tenant- or object-level rules ("may edit *this* document") in your own code. Roles answer "what kind of user is this?".
