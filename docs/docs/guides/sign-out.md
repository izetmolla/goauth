---
title: Sign-out
description: End a session, clear the cookie and Redis cache, and sign a user out on every device.
---

# Sign-out

A session stays valid until its row is marked `is_deleted = true` or it expires. Signing out means:

1. Mark the session row deleted. This stops the refresh token and the session cookie.
2. Remove the cached copy from Redis, if you use it.
3. Expire the session cookie in the browser.
4. Drop the tokens on the client.

Already issued **access tokens** keep working until they expire (`AccessTokenDuration`). That is why they should be short-lived.

## A sign-out handler

```go
func signOut(auth *goauth.Authorization, db *gorm.DB, rdb *redis.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := sessionIDFromRequest(auth, r)
		if sessionID != "" {
			db.WithContext(r.Context()).Table("sessions").
				Where("id = ?", sessionID).
				Update("is_deleted", true)
			if rdb != nil {
				rdb.Del(r.Context(), goauth.DefaultRedisPrefix+":"+sessionID)
			}
		}

		// Expire the session cookie. Path, Domain and Secure must match how it was set.
		http.SetCookie(w, &http.Cookie{
			Name:     goauth.DefaultCookieSessionName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
			SameSite: http.SameSiteLaxMode,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

// sessionIDFromRequest finds the session from the cookie (web) or the
// refresh token (API clients send it as "Authorization: Bearer <refresh>").
func sessionIDFromRequest(auth *goauth.Authorization, r *http.Request) string {
	if id := auth.GetSessionID(r); id != "" {
		return id
	}
	raw, err := auth.GetTokenFromHeader(r.Header.Get("Authorization"))
	if err != nil {
		return ""
	}
	claims, err := auth.ExtractToken(raw)
	if err != nil {
		return ""
	}
	return claims.SessionID
}
```

```go
mux.HandleFunc("POST /api/logout", signOut(auth, db, rdb))
```

:::tip
If you set a custom `RedisPrefix`, `CookieSessionName` or cookie `Domain` (see [Cross-subdomain SSO](./cross-subdomain-sso.md)), use the same values here.
:::

## Client side

```js
async function signOut() {
  const key = 'authorization-storage';
  const s = JSON.parse(localStorage.getItem(key) || '{"sessions":[]}');
  const current = s.sessions.find((x) => x.session_id === s.current_session);

  await fetch('/api/logout', {
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

## Sign out everywhere

Mark every session of the user as deleted, for example after a password change or when an account is disabled:

```go
func signOutEverywhere(ctx context.Context, db *gorm.DB, rdb *redis.Client, userID string) error {
	var ids []string
	if err := db.WithContext(ctx).Table("sessions").
		Where("user_id = ? AND is_deleted = ?", userID, false).
		Pluck("id", &ids).Error; err != nil {
		return err
	}
	if err := db.WithContext(ctx).Table("sessions").
		Where("user_id = ?", userID).
		Update("is_deleted", true).Error; err != nil {
		return err
	}
	if rdb != nil && len(ids) > 0 {
		keys := make([]string, len(ids))
		for i, id := range ids {
			keys[i] = goauth.DefaultRedisPrefix + ":" + id
		}
		return rdb.Del(ctx, keys...).Err()
	}
	return nil
}
```

Even without deleting the Redis keys, goauth re-checks `is_deleted` in the database on every cached lookup, so a signed-out session stops working right away. Deleting the keys just frees memory.

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
		db.WithContext(r.Context()).Table("sessions").
			Where("id = ? AND user_id = ?", r.PathValue("id"), data.UserID).
			Update("is_deleted", true)
		w.WriteHeader(http.StatusNoContent)
	})))
```
