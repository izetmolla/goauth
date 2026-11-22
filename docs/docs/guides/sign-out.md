---
title: Sign-out
description: Sign users out with the built-in endpoint, revoke sessions from your code, and sign a user out on every device.
---

# Sign-out

A session stays valid until it is revoked or it expires. Revoking a session marks its row `is_deleted = true`, which stops its refresh token and session cookie on the next request, and removes its Redis copy if you use Redis.

Already issued **access tokens** keep working until they expire (`AccessTokenDuration`). That is why they should be short-lived.

## The sign-out endpoint

`auth.Handler()` serves `POST /api/authorization/signout`. It finds the session, revokes it, expires the session cookie and answers `204 No Content`. The session is taken from:

- the **session cookie**, for browsers, or
- a **refresh token**, for API and mobile clients: `Authorization: Bearer <refresh_token>` or a JSON body `{"refresh_token": "..."}`.

A request without a session only clears the cookie and still answers `204`, so signing out twice is harmless. Turn the endpoint off with `Config.Endpoints.DisableSignOut`.

```bash
# Browser-style: with the session cookie
curl -X POST -b cookies.txt http://localhost:3000/api/authorization/signout

# API client: with the refresh token
curl -X POST -H "Authorization: Bearer $REFRESH_TOKEN" \
  http://localhost:3000/api/authorization/signout
```

## Signing out from your own handler

`auth.SignOut(w, r)` does the same work and returns an error instead of writing a response:

```go
mux.HandleFunc("POST /account/logout", func(w http.ResponseWriter, r *http.Request) {
	if err := auth.SignOut(w, r); err != nil {
		http.Error(w, "could not sign out", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
})
```

## Revoking sessions from your code

```go
// One session, for example from an "active devices" page.
err := auth.RevokeSession(ctx, sessionID)

// Every session of a user: after a password change, or when an account is disabled.
err := auth.RevokeUserSessions(ctx, userID)
```

Revoking an unknown or already revoked session is not an error. A successful password reset already signs the user out everywhere.

## Client side

```js
async function signOut() {
  const key = 'authorization-storage';
  const s = JSON.parse(localStorage.getItem(key) || '{"sessions":[]}');
  const current = s.sessions.find((x) => x.session_id === s.current_session);

  await fetch('/api/authorization/signout', {
    method: 'POST',
    credentials: 'include',
    headers: current ? {Authorization: `Bearer ${current.tokens.refresh_token}`} : {},
  });

  s.sessions = s.sessions.filter((x) => x.session_id !== s.current_session);
  s.current_session = s.sessions[0]?.session_id ?? '';
  localStorage.setItem(key, JSON.stringify(s));
  location.href = '/sign-in';
}
```

## Listing active sessions

Show users where they are signed in, and let them revoke a device:

```go
type activeSession struct {
	ID        string    `json:"id"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Method    string    `json:"method"`
	CreatedAt time.Time `json:"created_at"`
}

mux.Handle("GET /api/sessions", auth.UseAPIAuthorization()(http.HandlerFunc(
	func(w http.ResponseWriter, r *http.Request) {
		data, _ := auth.GetAuthDataAPI(r)
		var list []activeSession
		db.WithContext(r.Context()).Table("sessions").
			Where("user_id = ? AND is_deleted = ? AND expires_at > ?", data.UserID, false, time.Now()).
			Order("created_at DESC").
			Find(&list)
		json.NewEncoder(w).Encode(list)
	})))

mux.Handle("DELETE /api/sessions/{id}", auth.UseAPIAuthorization()(http.HandlerFunc(
	func(w http.ResponseWriter, r *http.Request) {
		data, _ := auth.GetAuthDataAPI(r)
		// Only revoke your own sessions.
		var owner string
		db.WithContext(r.Context()).Table("sessions").Select("user_id").
			Where("id = ?", r.PathValue("id")).Scan(&owner)
		if owner != data.UserID {
			http.NotFound(w, r)
			return
		}
		_ = auth.RevokeSession(r.Context(), r.PathValue("id"))
		w.WriteHeader(http.StatusNoContent)
	})))
```
