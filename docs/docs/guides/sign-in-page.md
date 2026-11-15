---
title: Built-in pages
description: The built-in sign-in, sign-up, forgot-password, one-time-code and verify-email pages, their endpoints, branding, and how to switch them on and off.
---

# Built-in pages

goauth ships ready-made pages, like Auth.js's built-in pages. The HTML, CSS and JS are compiled into your binary with `embed`, so there is nothing to deploy and no external requests.

Every page is **off by default**. Turn them on one by one, or all at once with `UI.EnableAllUI`:

| Page | Turn on | Default path | Change path with | Needs |
|---|---|---|---|---|
| Sign in | `UI.EnableSignInPage` | `/api/authorization/signin` | `UI.SignInEndpoint` | |
| Sign up | `UI.EnableRegisterPage` | `/api/authorization/register` | `UI.RegisterEndpoint` | `Endpoints.EnableRegister` and a provider with `Register` |
| Forgot password | `UI.EnableForgotPasswordPage` | `/api/authorization/forgot` | `UI.ForgotPasswordEndpoint` | `Verification.PasswordReset.Enabled` |
| One-time code | `UI.EnableOTPPage` | `/api/authorization/otp` | `UI.OTPEndpoint` | `Verification.OTPSignIn.Enabled` |
| Verify email | `UI.EnableVerifyPage` | `/api/authorization/verify-email` | `UI.VerifyEndpoint` | `Verification.EmailConfirmation.Enabled` |

`EnableAllUI` turns on every page whose feature is on and skips the others. Turning on a single page whose feature is off makes `New` return an error naming what's missing.

The sign-in page lists every configured provider as a **Continue with …** button and the email and password form of the first credentials provider. It links to the other pages only when they are on: **Forgot password?** under the password, **Email me a sign-in code**, and a **Sign in / Sign up** switch. Password reset, confirmation and one-time codes are covered in [Password reset, email confirmation and one-time codes](./verification.md).

- Light and dark themes follow the visitor's system setting, and the layout works at phone width.
- Works without JavaScript: links switch pages, forms post normally, and the server answers with the next step.
- With JavaScript:
  - errors appear inline without a reload, and buttons show a spinner
  - passwords can be revealed, and new passwords get live strength hints
  - codes are typed into segmented boxes that accept paste and submit themselves when full
  - "Resend email" counts down
  - the provider used last time gets a **Last used** badge
- After sign-in the session is stored in `localStorage` (`authorization-storage`) exactly like the OAuth callback page does, and the browser goes to `redirectUrl`.

## Turn the pages on

```go
auth, err := goauth.New(&goauth.Config{
	// ...
	UI: goauth.UIOptions{
		EnableAllUI: true, // or EnableSignInPage: true, EnableOTPPage: true, ...
	},
})

mux.Handle(goauth.DefaultBasePath+"/", auth.Handler())
```

### Your own paths

Serve the pages wherever you like, for example at the top level of your site:

```go
UI: goauth.UIOptions{
	EnableAllUI:            true,
	SignInEndpoint:         "/sign-in",
	RegisterEndpoint:       "/sign-up",
	ForgotPasswordEndpoint: "/forgot-password",
	OTPEndpoint:            "/login/code",
	VerifyEndpoint:         "/verify",
},
```

`auth.Handler()` serves the pages at those paths, so route them to it as well as the base path. The simplest way is to mount it at the root:

```go
mux.Handle("/", auth.Handler()) // your more specific routes still win
// or route only what you need:
mux.Handle(goauth.DefaultBasePath+"/", auth.Handler())
mux.Handle("/sign-in", auth.Handler())
mux.Handle("/sign-up", auth.Handler())
```

Everything follows the configured paths: links between pages, redirects after a form post without JavaScript, the links in verification emails, and the "back to sign in" link on the OAuth callback page. Set `SignInRedirectURL` to the same path so `UseWEBAuthorization` sends signed-out users there. Its default, `/sign-in`, already matches the example above.

Paths must be clean absolute paths (`/sign-in`, not `sign-in`, `/sign-in/` or `/x/{id}`), distinct from each other, and must not take an API route such as `{base}/csrf`. `New` reports any problem. The pages' CSS and JS stay at `{base}/assets/`.

Query parameters:

| Parameter | Effect |
|---|---|
| `redirectUrl` (or `callbackUrl`) | Where to go after signing in. Only same-origin targets are kept; anything else falls back to `UI.DefaultRedirect`. |
| `email` | Pre-fills the email on the forgot-password, one-time-code and verify pages. |

## Credentials sign-in and sign-up

Sign-up is **off by default**. Turn it on with `Endpoints.EnableRegister` and give the credentials provider a `Register` function:

```go
goauth.Config{
	Endpoints: goauth.EndpointOptions{EnableRegister: true},
}
```

```go
credentials.New(credentials.Options{
	Authorize: func(ctx context.Context, c map[string]string, r *http.Request) (*goauth.OAuthUser, error) {
		u, err := findUserByEmail(ctx, c["email"])
		if err != nil || !goauth.CheckPassword(u.PasswordHash, c["password"]) {
			return nil, &goauth.CredentialsError{Message: "Invalid email or password"}
		}
		return &goauth.OAuthUser{ID: u.ID, Email: u.Email, Name: u.Name}, nil
	},
	// With Endpoints.EnableRegister: the sign-up page and POST .../register.
	Register: func(ctx context.Context, f map[string]string, r *http.Request) (*goauth.OAuthUser, error) {
		if len(f["password"]) < 12 {
			return nil, &goauth.CredentialsError{Message: "Use at least 12 characters", Field: "password"}
		}
		hash, _ := goauth.HashPassword(f["password"])
		u, err := createUser(ctx, f["name"], f["email"], hash)
		if err != nil {
			return nil, &goauth.CredentialsError{Message: "That email is already registered", Field: "email"}
		}
		return &goauth.OAuthUser{ID: u.ID, Email: u.Email, Name: u.Name}, nil
	},
	RegisterFields: []goauth.CredentialField{
		{Name: "name", Label: "Full name"},
		{Name: "email", Label: "Email", Type: "email"},
		{Name: "password", Label: "Password", Type: "password"},
	},
}),
```

- `OAuthUser.ID` must be your user's id. goauth creates the session, loads the user's roles from the users table, and sets the session cookie.
- Return a `*goauth.CredentialsError` for a message the user should see. `Field` focuses that input. Any other error is shown as a generic "Something went wrong", so database errors never reach the browser.
- Returning `nil, nil` means "invalid credentials".
- A successful sign-up signs the new user in. With email confirmation and `RequireConfirmed`, it shows "Check your inbox" instead (see [verification](./verification.md)).
- goauth does not rate-limit these endpoints. Put a rate limiter in front of them (per IP and per email).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `UI.SignInEndpoint` (default `{base}/signin`) | Sign-in page (`UI.EnableSignInPage`) |
| `GET` | `UI.RegisterEndpoint` (default `{base}/register`) | Sign-up page (`UI.EnableRegisterPage`) |
| `GET` | `{base}/assets/{file}` | The pages' CSS and JS, served while any page is on (versioned, cached for a year) |
| `GET` | `{base}/csrf` | `{"csrfToken": "..."}` for single-page apps with their own form |
| `POST` | `{base}/provider/{id}` | Credentials sign-in |
| `POST` | `{base}/provider/{id}/register` | Credentials sign-up (`Endpoints.EnableRegister`) |

The forgot-password, one-time-code and verify-email endpoints are listed in [verification](./verification.md#4-endpoints).

Both POST endpoints accept a form-encoded or JSON body containing the provider's fields and `csrfToken` (plus an optional `redirectUrl`). Send `Accept: application/json` to get JSON:

```json
{"type": "sign_in", "user": {"id": "…", "email": "…"}, "tokens": {"access_token": "…", "refresh_token": "…"},
 "session_id": "…", "redirect_url": "/projects"}
```

Errors return `{"message", "code", "field"}` with status `401` (rejected), `403` (CSRF), `400` (bad body) or `500`. Without `Accept: application/json` (a plain form post), the user is redirected back to the page with an error code.

Mobile and API clients that do not use cookies send `X-Auth-Flow: token`. That skips the CSRF check and the session cookie, and always returns the refresh token. Only the header counts: `?flow=token` does not skip CSRF, because a cross-site form could add it to the URL.

## Switching parts on and off

The sign-in **APIs** (OAuth, credentials, `/providers`, `/csrf`) are on by default. Sign-up, the verification features and **every HTML page** are off until you turn them on:

```go
goauth.Config{
	Endpoints: goauth.EndpointOptions{
		EnableRegister:     true, // sign-up API (off by default)
		DisableCredentials: true, // no password sign-in at all
		DisableCSRF:        true, // no /csrf JSON endpoint (the pages still work)
		DisableProviders:   true, // no /providers JSON endpoint
	},
	UI: goauth.UIOptions{
		EnableAllUI: true, // every page whose feature is on
		// or one by one:
		// EnableSignInPage, EnableRegisterPage, EnableForgotPasswordPage, EnableOTPPage, EnableVerifyPage
	},
	Verification: goauth.VerificationOptions{
		PasswordReset:     goauth.PasswordResetOptions{Enabled: true},     // /forgot
		EmailConfirmation: goauth.EmailConfirmationOptions{Enabled: true}, // /verify-email
		OTPSignIn:         goauth.OTPSignInOptions{Enabled: true},         // /otp
		// ... callbacks, see the verification guide
	},
}
```

An endpoint or page that is off answers `404` (or `405` where only a POST API lives at that path), including when you mount its exported handler yourself (`auth.SignInPage`, `auth.RegisterPage`, `auth.ForgotPasswordPage`, `auth.OTPPage`, `auth.VerifyEmailPage`, `auth.HandleRegister`, …). Pages link to each other only when the target page is on. When the sign-in page is off, "Back to sign in" points to `SignInRedirectURL`.

`Endpoints.DisablePages` still forces every page off. It is deprecated, since pages are off unless you turn them on.

## Branding

```go
goauth.Config{
	UI: goauth.UIOptions{
		AppName:         "Flowtrove",                 // "Sign in to Flowtrove"
		LogoURL:         "/static/logo.svg",          // replaces the lock icon
		AccentColor:     "#7c3aed",                   // buttons, links, focus rings
		TermsURL:        "https://example.com/terms",
		PrivacyURL:      "https://example.com/privacy",
		DefaultRedirect: "/dashboard",                // default "/"
	},
}
```

`New` rejects an `AccentColor` that is not a plain CSS color, and a `DefaultRedirect` that is not a same-origin path.

## Security

The page sends a strict `Content-Security-Policy`:
- `script-src 'self'`, with no inline scripts
- styles only from the stylesheet, plus a nonce for the accent color
- `frame-ancestors 'none'`

It also sends `X-Frame-Options: DENY` and `Cache-Control: no-store`. Forms use the signed double-submit CSRF cookie. A valid cookie is reused, so several open tabs keep working.

Provider buttons have built-in icons for Google, GitHub, Microsoft / Azure AD and LDAP / SSO. Any other provider gets a letter badge.
