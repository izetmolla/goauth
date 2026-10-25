---
title: OAuth sign-in
description: Sign-in links, popup sign-in, ResolveUser patterns and the built-in callback page.
---

# OAuth sign-in

This guide covers the full OAuth / OpenID Connect sign-in flow, from a plain link to a popup window.

## Step 1: Register a provider

```go
auth, err := goauth.New(&goauth.Config{
	JWTSecret: os.Getenv("JWT_SECRET"),
	AuthURL:   "https://app.example.com",
	DB:        db,
	Providers: []goauth.Provider{
		google.New(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")),
	},
	ResolveUser: resolveUser,
})
```

At the provider, register this redirect URI (replace `google` with the provider id):

```text
https://app.example.com/api/authorization/provider/google/callback
```

## Step 2: Write `ResolveUser`

```go
func(ctx context.Context, profile goauth.Profile) (user *goauth.User, isNew bool, err error)
```

- `profile` is the raw userinfo JSON from the provider, plus `provider` and `providerType` keys added by goauth.
- Return the user's `ID` (written into tokens and the session) and `Roles`.
- `isNew` is for your own bookkeeping; goauth ignores it today.
- Returning an error, a nil user, or an empty `ID` aborts the sign-in and shows the error on the callback page.

### Simple: find or create by email

```go
func resolveUser(db *gorm.DB) func(context.Context, goauth.Profile) (*goauth.User, bool, error) {
	return func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
		email, _ := p["email"].(string)
		if email == "" {
			return nil, false, errors.New("email is required")
		}
		var u User // your GORM model: ID, Email, Name, Roles goauth.JSONBArray
		err := db.WithContext(ctx).Where("email = ?", email).First(&u).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u = User{Email: email, Name: fmt.Sprint(p["name"]), Roles: goauth.JSONBArray{"user:r"}}
			if err := db.WithContext(ctx).Create(&u).Error; err != nil {
				return nil, false, err
			}
			return &goauth.User{ID: u.ID, Roles: u.Roles}, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		return &goauth.User{ID: u.ID, Roles: u.Roles}, false, nil
	}
}
```

### Allow-list: only known users may sign in

```go
ResolveUser: func(ctx context.Context, p goauth.Profile) (*goauth.User, bool, error) {
	email, _ := p["email"].(string)
	var u User
	if err := db.WithContext(ctx).Where("email = ?", email).First(&u).Error; err != nil {
		return nil, false, fmt.Errorf("%s is not invited", email)
	}
	return &goauth.User{ID: u.ID, Roles: u.Roles}, false, nil
},
```

### Domain restriction

```go
email, _ := p["email"].(string)
if verified, _ := p["email_verified"].(bool); !verified || !strings.HasSuffix(email, "@example.com") {
	return nil, false, errors.New("only verified @example.com accounts may sign in")
}
```

### One user, several providers

Users may sign in with Google today and Microsoft tomorrow. Keep a separate table that maps `(provider, provider subject)` to your user id:

```go
provider, _ := p["provider"].(string) // "google", "azuread-v2", ...
subject := fmt.Sprint(cmp.Or(p["sub"], p["id"], p["oid"]))

var link struct{ UserID string }
err := db.WithContext(ctx).Table("user_identities").
	Where("provider = ? AND subject = ?", provider, subject).
	Take(&link).Error
// not found → look up by verified email, or create the user, then insert the link
```

### Adding custom data to the browser

`goauth.User.User` is copied into the `user` object the callback page stores in the browser (it is never written to the database or into tokens):

```go
return &goauth.User{
	ID:    u.ID,
	Roles: u.Roles,
	User:  goauth.JSONBAny{"email": u.Email, "name": u.Name, "avatar": p["picture"]},
}, false, nil
```

## Step 3: Start sign-in from the browser

### A plain link

```html
<a href="/api/authorization/provider/google">Sign in with Google</a>
```

### Buttons for every provider

```js
const providers = await fetch('/api/authorization/providers').then((r) => r.json());
for (const p of providers) {
  const a = document.createElement('a');
  a.href = p.signinUrl;
  a.textContent = `Sign in with ${p.name}`;
  document.querySelector('#providers').append(a);
}
```

### Popup window

A popup keeps your app's state (open forms, scroll position) intact. When the callback page sees `window.opener`, it sends a message to the opener and closes itself:

```js
function signInWithPopup(providerId) {
  return new Promise((resolve, reject) => {
    const popup = window.open(
      `/api/authorization/provider/${providerId}`,
      'goauth',
      'width=500,height=650',
    );
    if (!popup) return reject(new Error('Popup blocked'));

    function onMessage(event) {
      if (event.origin !== window.location.origin) return;
      if (event.data?.type !== 'authorization-sign-in') return;
      window.removeEventListener('message', onMessage);
      resolve(event.data.session_id);
    }
    window.addEventListener('message', onMessage);
  });
}

const sessionId = await signInWithPopup('google');
const store = JSON.parse(localStorage.getItem('authorization-storage'));
const session = store.sessions.find((s) => s.session_id === sessionId);
console.log(session.user, session.tokens.access_token);
```

### Ask for the URL as JSON

To control the redirect yourself (for example in a mobile web view), ask for JSON:

```js
const {url} = await fetch('/api/authorization/provider/google?json=true', {
  credentials: 'include', // the state/PKCE cookies must be stored
}).then((r) => r.json());
window.location.assign(url);
```

## The callback page

After a successful callback, goauth renders a small HTML page (light and dark themes, no external assets). On success it:

1. Saves the session under the `localStorage` key **`authorization-storage`**:

   ```json
   {
     "sessions": [
       {
         "session_id": "3f0c...",
         "user": {"id": "5b1c...", "roles": ["admin:rw"]},
         "tokens": {"access_token": "eyJ...", "refresh_token": "eyJ..."},
         "trusted": false
       }
     ],
     "current_session": "3f0c...",
     "redirectUrl": ""
   }
   ```

   The shape is compatible with a [zustand](https://github.com/pmndrs/zustand) `persist` store, and several signed-in accounts can live side by side.

2. If opened as a popup: posts `{type: "authorization-sign-in", session_id}` to the opener (same origin only) and closes.
3. Otherwise: redirects to the stored `redirectUrl`, or `/`.

To send users somewhere specific after sign-in, write `redirectUrl` before starting the flow:

```js
const key = 'authorization-storage';
const s = JSON.parse(localStorage.getItem(key) || '{"sessions":[],"current_session":""}');
s.redirectUrl = '/settings';
localStorage.setItem(key, JSON.stringify(s));
location.href = '/api/authorization/provider/google';
```

On failure, the page shows the error message and a **Back to sign in** button that goes to `/sign-in`.

The session cookie is set as well, so server-rendered pages protected by `UseWEBAuthorization` work right away.

## Security checks

Each `OAuthProvider` lists the checks it uses in `Checks`:

| Check | Protects against | How |
|---|---|---|
| `goauth.CheckState` | CSRF on the callback | Random value in a cookie, compared in constant time with the `state` parameter |
| `goauth.CheckPKCE` | Stolen authorization codes | S256 `code_challenge`; the verifier is sent with the code exchange |
| `goauth.CheckNonce` | ID-token replay | Random `nonce` sent to the provider |

The built-in Google and Azure AD providers enable all three. Flow cookies expire after 15 minutes and are cleared on every new attempt and every callback.

:::caution[Current limitation]
goauth sends the `nonce` but does not yet validate the ID token's signature or `nonce` claim. It identifies the user from the userinfo endpoint, called with the fresh access token over TLS. If you depend on ID-token claims, verify the ID token yourself in your provider's `Profile` function.
:::

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `redirect_uri_mismatch` at the provider | `AuthURL` or the registered redirect URI differs (scheme, host, port, or provider id) |
| "State mismatch" | The browser dropped the state cookie: the callback host differs from the sign-in host, or more than 15 minutes passed |
| "ResolveUser() function is not set" | `Config.ResolveUser` is nil |
| "Provider missing AuthorizationURL" | A custom provider has neither `Issuer` nor `AuthorizationURL` |
| Signed in, but `/dashboard` redirects back | The session cookie was set for another host; check `AuthURL` and [cookie domains](./cookies.md) |
