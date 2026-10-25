---
title: Credentials sign-in
description: Build email and password sign-up and sign-in with HashPassword, CheckPassword and Authorize.
---

# Credentials sign-in (email and password)

goauth gives you the building blocks for password sign-in:

- `goauth.HashPassword` / `goauth.CheckPassword` for PBKDF2-SHA256 hashing
- `auth.Authorize` to create a session and sign tokens
- `auth.SetSessionIDCookie` for browser sessions

You write a small `POST /login` handler that ties them together. This keeps full control over your user table, validation, rate limiting and error messages.

:::note[About the credentials provider]
The `credentials` provider (see [Credentials provider](../providers/credentials.md)) lists a password form in `/providers` and enforces `POST` and CSRF on its sign-in endpoint. It does not call `Authorize` yet, so use the handler on this page for the actual sign-in.
:::

## Password hashing

```go
hash, err := goauth.HashPassword("correct horse battery staple")
// $pbkdf2-sha256$600000$<salt>$<hash>

ok := goauth.CheckPassword(hash, "correct horse battery staple") // true
```

- PBKDF2 with SHA-256, a random 16-byte salt and a self-describing format: `$pbkdf2-sha256$<iterations>$<salt>$<hash>`.
- `CheckPassword` reads the iteration count from the hash, so stored hashes keep working if the default changes.
- Comparison runs in constant time.

## Schema

Add a password column to your users table:

```sql
ALTER TABLE users ADD COLUMN password_hash text;
```

## Sign-up

```go
type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func signUp(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in credentials
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		in.Email = strings.ToLower(strings.TrimSpace(in.Email))
		if in.Email == "" || len(in.Password) < 12 {
			http.Error(w, "email and a password of at least 12 characters are required", http.StatusBadRequest)
			return
		}
		hash, err := goauth.HashPassword(in.Password)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		err = db.WithContext(r.Context()).Exec(
			`INSERT INTO users (id, email, password_hash, roles) VALUES (?, ?, ?, ?)`,
			uuid.NewString(), in.Email, hash, goauth.JSONBArray{"user:r"},
		).Error
		if err != nil {
			http.Error(w, "email already registered", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}
```

## Sign-in

```go
// dummyHash keeps the response time the same whether or not the email exists.
var dummyHash, _ = goauth.HashPassword("dummy-password-for-timing")

func signIn(db *gorm.DB, auth *goauth.Authorization) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in credentials
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		var user struct {
			ID           string
			PasswordHash string
		}
		err := db.WithContext(r.Context()).Table("users").
			Select("id", "password_hash").
			Where("email = ?", strings.ToLower(strings.TrimSpace(in.Email))).
			Take(&user).Error
		hash := user.PasswordHash
		if err != nil || hash == "" {
			hash = dummyHash
		}
		if !goauth.CheckPassword(hash, in.Password) || err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "invalid email or password"})
			return
		}

		opts := append([]goauth.AuthorizeOptionsFunc{auth.WithUserID(user.ID)},
			auth.SessionMetaFromRequest(r, "password")...)
		tokens, sessionID, err := auth.Authorize(opts...)
		if err != nil {
			http.Error(w, "could not create session", http.StatusInternalServerError)
			return
		}

		// Browser pages protected by UseWEBAuthorization need the cookie.
		auth.SetSessionIDCookie(w, r, sessionID)

		writeJSON(w, http.StatusOK, map[string]any{
			"session_id": sessionID,
			"user_id":    user.ID,
			"tokens":     tokens,
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
```

Register the routes:

```go
mux.HandleFunc("POST /api/signup", signUp(db))
mux.HandleFunc("POST /api/login", signIn(db, auth))
```

Try it:

```bash
curl -X POST localhost:3000/api/signup -d '{"email":"jane@example.com","password":"a-long-passphrase"}'
curl -X POST localhost:3000/api/login  -d '{"email":"jane@example.com","password":"a-long-passphrase"}' -c cookies.txt
```

```json
{
  "session_id": "3f0c9a51-...",
  "user_id": "5b1c2f7e-...",
  "tokens": {"access_token": "eyJ...", "refresh_token": "eyJ..."}
}
```

The new session works with every goauth feature: the API middleware, the web middleware, [refresh](./tokens-and-refresh.md) and [sign-out](./sign-out.md).

## Storing the tokens like the OAuth callback page does

To let password and OAuth sign-ins share the same browser state, save the response in the same `authorization-storage` format:

```js
const res = await fetch('/api/login', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email, password}),
});
if (!res.ok) throw new Error((await res.json()).message);
const {session_id, user_id, tokens} = await res.json();

const key = 'authorization-storage';
const s = JSON.parse(localStorage.getItem(key) || '{"sessions":[],"current_session":"","redirectUrl":""}');
s.sessions = s.sessions.filter((x) => x.session_id !== session_id);
s.sessions.push({session_id, user: {id: user_id}, tokens, trusted: false});
s.current_session = session_id;
localStorage.setItem(key, JSON.stringify(s));
```

## Hardening checklist

- **Rate limit** `/api/login` per IP and per email, for example with [`golang.org/x/time/rate`](https://pkg.go.dev/golang.org/x/time/rate).
- Return the same message for "unknown email" and "wrong password" (done above).
- Require HTTPS so the password and the `Secure` cookie are protected.
- Re-hash on sign-in when you raise the iteration count: compare the iterations in the stored hash and call `HashPassword` again if they are lower.
- For directory accounts, verify passwords against LDAP instead. See [LDAP](../providers/ldap.md).
