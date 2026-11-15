---
title: Password reset, email confirmation and one-time codes
description: Turn on "Forgot password?", account confirmation and passwordless sign-in, configure codes and links, and customise the emails.
---

# Password reset, email confirmation and one-time codes

goauth can send verification emails for three features. All three are **off by default**:

| Feature | What the user does | Pages | Default delivery |
|---|---|---|---|
| **Password reset** | "Forgot password?" → email → choose a new password | `/forgot` | Link |
| **Email confirmation** | Confirm their address after signing up | `/verify-email` | Link |
| **One-time code sign-in** | Sign in with a code (or magic link) instead of a password | `/otp` | Code + link |

Codes and links are stored in a **verification table**, only as keyed hashes. Each one works once, expires, and allows a limited number of wrong attempts. goauth renders the emails from built-in templates; you deliver them with your own mail provider.

## 1. Create the verification table

The easiest way is to let goauth create it with GORM. The column types are portable across PostgreSQL, MySQL, SQLite and SQL Server:

```go
if err := auth.MigrateVerificationTokens(ctx); err != nil {
	log.Fatal(err)
}
```

Or create it yourself. The table name defaults to `verification_tokens` (see `Verification.TableName`):

```sql
-- PostgreSQL
CREATE TABLE verification_tokens (
    id          varchar(36) PRIMARY KEY,
    kind        varchar(32)  NOT NULL,
    identifier  varchar(255) NOT NULL,
    user_id     varchar(64)  NOT NULL,
    token_hash  varchar(64),
    code_hash   varchar(64),
    attempts    bigint       NOT NULL,
    expires_at  timestamptz  NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz  NOT NULL
);
CREATE INDEX idx_goauth_verification_lookup ON verification_tokens (kind, identifier);
CREATE INDEX idx_goauth_verification_token  ON verification_tokens (token_hash);
```

For MySQL use `datetime(3)` instead of `timestamptz`. For SQL Server use `nvarchar` and `datetimeoffset`. For SQLite use `TEXT`, `INTEGER` and `DATETIME`. Times are always written in UTC, and expiry is checked in Go, so no database time functions are used.

## 2. Connect it to your users

goauth never touches your users table directly. You give it four small callbacks:

```go
auth, err := goauth.New(&goauth.Config{
	// ...
	Verification: goauth.VerificationOptions{
		PasswordReset:     goauth.PasswordResetOptions{Enabled: true},
		EmailConfirmation: goauth.EmailConfirmationOptions{Enabled: true},
		OTPSignIn:         goauth.OTPSignInOptions{Enabled: true},

		// Look a user up by email. Return (nil, nil) if there is none.
		FindUser: func(ctx context.Context, email string) (*goauth.OAuthUser, error) {
			u, err := users.ByEmail(ctx, email)
			if errors.Is(err, ErrNotFound) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			return &goauth.OAuthUser{ID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified}, nil
		},
		// Deliver the email. Subject, HTML and Text are already rendered.
		Send: func(ctx context.Context, m *goauth.VerificationMessage) error {
			return mailer.Send(ctx, m.To, m.Subject, m.HTML, m.Text)
		},
		// Store a new password (password reset).
		SetPassword: func(ctx context.Context, userID, password string) error {
			hash, err := goauth.HashPassword(password)
			if err != nil {
				return err
			}
			return users.SetPasswordHash(ctx, userID, hash)
		},
		// Record that the email is confirmed (email confirmation).
		MarkVerified: func(ctx context.Context, userID string) error {
			return users.SetEmailVerified(ctx, userID)
		},
		// Optional: log failures from the background work.
		OnError: func(ctx context.Context, kind goauth.VerificationKind, email string, err error) {
			slog.ErrorContext(ctx, "verification email failed", "kind", kind, "err", err)
		},
	},
})
```

`New` returns an error if an enabled feature is missing a callback it needs:

| Callback | Needed for |
|---|---|
| `FindUser`, `Send` | Any feature |
| `SetPassword` | Password reset |
| `MarkVerified` | Email confirmation. Also called after a password reset or a one-time sign-in, since those prove the same thing. |

### Privacy and timing

The "send me a code" endpoints answer the same way whether or not the email belongs to an account. The lookup, the database writes and `Send` all run **in the background** after the response, so response timing doesn't reveal anything either. Errors from that work go to `OnError`.

## 3. Codes, links and limits

Each feature takes a `Code` block. Every field is optional:

```go
OTPSignIn: goauth.OTPSignInOptions{
	Enabled: true,
	Code: goauth.CodeOptions{
		Length:      8,                         // 4–12, default 6
		Charset:     goauth.CharsetUnambiguous, // default CharsetNumeric
		TTL:         15 * time.Minute,          // default: 30m reset, 24h confirm, 10m OTP
		MaxAttempts: 5,                         // wrong codes before it is burned, default 5
		ResendAfter: time.Minute,               // min gap between emails, default 60s (negative = off)
		Delivery:    goauth.DeliverCodeAndLink, // DeliverCode | DeliverLink | DeliverCodeAndLink
	},
},
```

| Charset | Characters |
|---|---|
| `CharsetNumeric` | `0-9` |
| `CharsetAlpha` | `A-Z` |
| `CharsetAlphanumeric` | `A-Z0-9` |
| `CharsetUnambiguous` | `A-Z2-9` without `0 O 1 I L`, for codes people copy by hand |
| any string | your own characters (2–128 distinct printable ASCII characters) |

- Codes are drawn uniformly from the charset with `crypto/rand`.
- When the charset has no lower-case letters, codes match case-insensitively. Spaces and dashes are ignored, so `ab12 cd34` matches `AB12CD34`.
- Sending a new code retires the previous one.
- Requests inside `ResendAfter` are ignored silently. The response is the same as for a real send.

Password reset has two more options:

| Option | Default | Effect |
|---|---|---|
| `MinPasswordLength` | `8` | Minimum length of the new password |
| `KeepSessions` | `false` | By default every session of the user is signed out after a reset |

Email confirmation has one:

| Option | Default | Effect |
|---|---|---|
| `RequireConfirmed` | `false` | Credentials sign-in is refused until `OAuthUser.EmailVerified` is true (with a fresh confirmation email). Sign-up then waits for confirmation instead of signing the user in. |

Without `RequireConfirmed`, a confirmation email is still sent after sign-up, but the user is signed in right away.

### Links are safe from email scanners

Some mail systems open every link in an email to scan it. If opening a link did the action, those scanners would use up the link before the user ever clicked it. So in goauth, opening a link only shows a page with one button ("Continue", "Confirm email", or a new-password form), and the button does the action with a POST. The page also removes the token from the address bar and sends `Referrer-Policy: no-referrer`.

## 4. Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `{base}/forgot` | Forgot-password page |
| `POST` | `{base}/password/forgot` | Send reset email (`email`) |
| `GET` | `{base}/password/reset?email&token` | Reset link landing page |
| `POST` | `{base}/password/reset` | Set password (`email`, `code` or `token`, `password`) |
| `GET` | `{base}/otp` | One-time code page |
| `POST` | `{base}/otp/send` | Send code (`email`) |
| `GET` | `{base}/otp/verify?email&token` | Magic link landing page |
| `POST` | `{base}/otp/verify` | Sign in (`email`, `code` or `token`) |
| `GET` | `{base}/verify-email` | Confirm page (also the link landing page) |
| `POST` | `{base}/verify-email/send` | (Re)send confirmation (`email`) |
| `POST` | `{base}/verify-email` | Confirm (`email`, `code` or `token`) |

They exist only while the feature is enabled; otherwise they answer `404`. Every POST needs the CSRF token (`csrfToken`) unless the request sends `X-Auth-Flow: token`.

With `Accept: application/json`, the responses look like this:

```json
{"type": "step", "step": "code", "email": "jane@example.com", "message": "…",
 "resend_after": 60, "code_length": 6, "has_code": true, "has_link": true}
```

`step` is `code` (enter the code), `sent` (check your email), or `done` (finished). A successful one-time sign-in returns the same `sign_in` payload as a password sign-in. Errors use `{"message", "code", "field"}`, for example `INVALID_CODE`, `WEAK_PASSWORD` or `EMAIL_NOT_VERIFIED`.

If you build your own UI with `Endpoints.DisablePages`, links have nowhere to land, so set `Delivery: goauth.DeliverCode`. `New` tells you if you forget.

## 5. Email templates

The built-in emails use a table layout with inline styles, which works in Gmail, Outlook and Apple Mail. They use your `UI.AppName`, `UI.LogoURL` and `UI.AccentColor`. Each email has an HTML part and a plain-text part, and includes the code, the button link, a copyable link and the expiry ("10 minutes").

To change them, pass your own files in `Verification.EmailTemplates` (any `fs.FS`, for example `embed.FS`). Override only what you need; missing files fall back to the built-in ones.

| File | Defines |
|---|---|
| `password_reset.html` | `subject`, `preheader`, `text`, `html` |
| `email_confirmation.html` | `subject`, `preheader`, `text`, `html` |
| `otp_signin.html` | `subject`, `preheader`, `text`, `html` |
| `layout.html` (optional) | `layout` (the HTML shell), plus the `button` and `code` blocks |

```go
//go:embed emails
var emails embed.FS

sub, _ := fs.Sub(emails, "emails")
Verification: goauth.VerificationOptions{EmailTemplates: sub, ...}
```

```html
{{define "subject"}}{{.Code}} is your {{.AppName}} code{{end}}
{{define "preheader"}}Expires in {{.ExpiresIn}}{{end}}
{{define "text"}}Your code: {{.Code}}
{{if .Link}}Or open: {{.Link}}{{end}}{{end}}
{{define "html"}}<p>Your code is <b>{{.Code}}</b>.</p>{{if .Link}}{{template "button" .}}{{end}}{{end}}
```

Templates receive `EmailData`: `Kind`, `AppName`, `LogoURL`, `Initial`, `Accent`, `Email`, `Code`, `Link`, `ButtonLabel`, `ExpiresIn`. The subject and text parts are rendered without HTML escaping, so links stay intact. The HTML part is escaped as usual. Template errors are reported by `New`.
