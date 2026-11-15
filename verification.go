package goauth

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/mail"
	"strings"
	"time"
)

// VerificationKind names what a verification code or link is for.
type VerificationKind string

const (
	KindPasswordReset     VerificationKind = "password_reset"
	KindEmailConfirmation VerificationKind = "email_confirmation"
	KindOTPSignIn         VerificationKind = "otp_signin"
)

// Delivery chooses what a verification email contains.
type Delivery int

const (
	// DeliverDefault uses the feature's default: a link for password reset
	// and email confirmation, a code plus a link for one-time sign-in.
	DeliverDefault Delivery = iota
	// DeliverCode sends only a code the user types in.
	DeliverCode
	// DeliverLink sends only a link the user clicks.
	DeliverLink
	// DeliverCodeAndLink sends both; either one works.
	DeliverCodeAndLink
)

func (d Delivery) hasCode() bool { return d == DeliverCode || d == DeliverCodeAndLink }
func (d Delivery) hasLink() bool { return d == DeliverLink || d == DeliverCodeAndLink }

// Character sets for generated codes. Any string of 2 or more distinct
// printable ASCII characters can be used as CodeOptions.Charset.
const (
	CharsetNumeric      = "0123456789"
	CharsetAlpha        = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	CharsetAlphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// CharsetUnambiguous leaves out characters that are easy to misread
	// (0/O, 1/I/L), for codes people copy by hand.
	CharsetUnambiguous = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
)

// CodeOptions configures the codes and links one feature sends. Zero values
// take the feature's defaults.
type CodeOptions struct {
	// Length of generated codes: 4 to 12. Default 6.
	Length int
	// Charset codes are drawn from. Default CharsetNumeric. When it has no
	// lower-case letters, codes are matched case-insensitively.
	Charset string
	// TTL is how long a code or link stays valid. Defaults: 30 minutes for
	// password reset, 24 hours for email confirmation, 10 minutes for
	// one-time sign-in. At most 7 days.
	TTL time.Duration
	// MaxAttempts is how many wrong codes are accepted before the code is
	// burned. 1 to 20. Default 5.
	MaxAttempts int
	// ResendAfter is the minimum time between two emails to the same
	// address for the same feature. Requests inside it are silently
	// ignored. Default 60 seconds; set a negative value to disable.
	ResendAfter time.Duration
	// Delivery chooses code, link or both. See Delivery.
	Delivery Delivery
}

// PasswordResetOptions configures "Forgot password?".
type PasswordResetOptions struct {
	Enabled bool
	Code    CodeOptions
	// MinPasswordLength for the new password. Default 8.
	MinPasswordLength int
	// KeepSessions leaves the user's other sessions signed in after a reset.
	// By default every session is signed out.
	KeepSessions bool
}

// EmailConfirmationOptions configures account (email) confirmation.
type EmailConfirmationOptions struct {
	Enabled bool
	Code    CodeOptions
	// RequireConfirmed blocks credentials sign-in until the address is
	// confirmed (OAuthUser.EmailVerified), and makes sign-up wait for
	// confirmation instead of signing the user in.
	RequireConfirmed bool
}

// OTPSignInOptions configures passwordless sign-in with a one-time code
// (and, by default, a magic link) sent by email.
type OTPSignInOptions struct {
	Enabled bool
	Code    CodeOptions
}

// VerificationOptions enables and configures password reset, email
// confirmation and one-time-code sign-in. Every feature is off by default.
// Codes and links are stored (hashed) in a verification table; see
// VerificationToken and MigrateVerificationTokens.
type VerificationOptions struct {
	PasswordReset     PasswordResetOptions
	EmailConfirmation EmailConfirmationOptions
	OTPSignIn         OTPSignInOptions

	// FindUser looks a user up by email. Return (nil, nil) when there is no
	// such user; goauth then answers exactly as if there were, so the
	// endpoints cannot be used to find out who has an account. Required
	// when any feature is enabled.
	FindUser func(ctx context.Context, email string) (*OAuthUser, error)
	// Send delivers a verification message (msg.Subject, msg.HTML and
	// msg.Text are already rendered). It runs in the background after the
	// HTTP response, so its timing does not reveal whether the account
	// exists. Required when any feature is enabled.
	Send func(ctx context.Context, msg *VerificationMessage) error
	// SetPassword stores a new password for userID (hash it, for example
	// with HashPassword). Required for password reset.
	SetPassword func(ctx context.Context, userID, password string) error
	// MarkVerified records that userID's email is confirmed. Required for
	// email confirmation; also called after a successful password reset or
	// one-time sign-in, which prove the same thing.
	MarkVerified func(ctx context.Context, userID string) error
	// OnError receives errors from the background work (FindUser, the
	// database, Send). Default: ignored.
	OnError func(ctx context.Context, kind VerificationKind, email string, err error)

	// TableName of the verification table. Default "verification_tokens".
	TableName string
	// EmailTemplates overrides the built-in emails. Provide any of
	// "password_reset.html", "email_confirmation.html", "otp_signin.html"
	// (each defining "subject", "text" and "html") and optionally
	// "layout.html". See the email templates guide.
	EmailTemplates fs.FS
}

// VerificationMessage is one email for VerificationOptions.Send.
type VerificationMessage struct {
	Kind      VerificationKind
	To        string
	UserID    string
	Code      string // "" when the delivery has no code
	Link      string // "" when the delivery has no link
	ExpiresAt time.Time

	Subject string
	Text    string
	HTML    string
}

// VerificationToken is a row of the verification table. Codes and link
// tokens are stored only as keyed hashes. The column tags are portable
// across GORM drivers (PostgreSQL, MySQL, SQLite, SQL Server).
type VerificationToken struct {
	ID         string           `gorm:"primaryKey;size:36"`
	Kind       VerificationKind `gorm:"size:32;not null;index:idx_goauth_verification_lookup,priority:1"`
	Identifier string           `gorm:"size:255;not null;index:idx_goauth_verification_lookup,priority:2"`
	UserID     string           `gorm:"size:64;not null"`
	TokenHash  string           `gorm:"size:64;index:idx_goauth_verification_token"`
	CodeHash   string           `gorm:"size:64"`
	Attempts   int              `gorm:"not null"`
	ExpiresAt  time.Time        `gorm:"not null"`
	ConsumedAt *time.Time
	CreatedAt  time.Time `gorm:"not null"`
}

// --- Resolved configuration -------------------------------------------------

// verifyFeature is one feature's configuration after defaults.
type verifyFeature struct {
	kind    VerificationKind
	enabled bool
	code    CodeOptions
}

type verification struct {
	opts    VerificationOptions
	table   string
	key     []byte // HKDF-derived key for hashing codes and link tokens
	reset   verifyFeature
	confirm verifyFeature
	otp     verifyFeature
	emails  *emailTemplates
}

func (v *verification) anyEnabled() bool {
	return v.reset.enabled || v.confirm.enabled || v.otp.enabled
}

const defaultVerificationTable = "verification_tokens"

func resolveCode(c CodeOptions, ttl time.Duration, delivery Delivery, name string) (CodeOptions, error) {
	if c.Length == 0 {
		c.Length = 6
	}
	if c.Length < 4 || c.Length > 12 {
		return c, fmt.Errorf("%s.Code.Length must be between 4 and 12", name)
	}
	if c.Charset == "" {
		c.Charset = CharsetNumeric
	}
	if err := validCharset(c.Charset); err != nil {
		return c, fmt.Errorf("%s.Code.Charset: %w", name, err)
	}
	if c.TTL == 0 {
		c.TTL = ttl
	}
	if c.TTL < time.Minute || c.TTL > 7*24*time.Hour {
		return c, fmt.Errorf("%s.Code.TTL must be between 1 minute and 7 days", name)
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 5
	}
	if c.MaxAttempts < 1 || c.MaxAttempts > 20 {
		return c, fmt.Errorf("%s.Code.MaxAttempts must be between 1 and 20", name)
	}
	if c.ResendAfter == 0 {
		c.ResendAfter = time.Minute
	}
	if c.Delivery == DeliverDefault {
		c.Delivery = delivery
	}
	if c.Delivery < DeliverCode || c.Delivery > DeliverCodeAndLink {
		return c, fmt.Errorf("%s.Code.Delivery is not a valid Delivery", name)
	}
	return c, nil
}

func validCharset(s string) error {
	if len(s) < 2 || len(s) > 128 {
		return errors.New("needs 2 to 128 characters")
	}
	seen := map[rune]bool{}
	for _, r := range s {
		if r <= ' ' || r > '~' {
			return errors.New("only printable ASCII characters without spaces are allowed")
		}
		if seen[r] {
			return fmt.Errorf("duplicate character %q", r)
		}
		seen[r] = true
	}
	return nil
}

func newVerification(o VerificationOptions, secret string) (*verification, error) {
	v := &verification{opts: o, table: o.TableName}
	if v.table == "" {
		v.table = defaultVerificationTable
	}
	var err error
	v.reset = verifyFeature{kind: KindPasswordReset, enabled: o.PasswordReset.Enabled}
	if v.reset.code, err = resolveCode(o.PasswordReset.Code, 30*time.Minute, DeliverLink, "PasswordReset"); err != nil {
		return nil, err
	}
	v.confirm = verifyFeature{kind: KindEmailConfirmation, enabled: o.EmailConfirmation.Enabled}
	if v.confirm.code, err = resolveCode(o.EmailConfirmation.Code, 24*time.Hour, DeliverLink, "EmailConfirmation"); err != nil {
		return nil, err
	}
	v.otp = verifyFeature{kind: KindOTPSignIn, enabled: o.OTPSignIn.Enabled}
	if v.otp.code, err = resolveCode(o.OTPSignIn.Code, 10*time.Minute, DeliverCodeAndLink, "OTPSignIn"); err != nil {
		return nil, err
	}
	if v.anyEnabled() {
		if o.FindUser == nil || o.Send == nil {
			return nil, errors.New("Verification.FindUser and Verification.Send are required when a verification feature is enabled")
		}
		if v.reset.enabled && o.SetPassword == nil {
			return nil, errors.New("Verification.SetPassword is required for PasswordReset")
		}
		if v.confirm.enabled && o.MarkVerified == nil {
			return nil, errors.New("Verification.MarkVerified is required for EmailConfirmation")
		}
	}
	if v.reset.enabled {
		if o.PasswordReset.MinPasswordLength == 0 {
			v.opts.PasswordReset.MinPasswordLength = 8
		}
		if v.opts.PasswordReset.MinPasswordLength < 1 || v.opts.PasswordReset.MinPasswordLength > 128 {
			return nil, errors.New("PasswordReset.MinPasswordLength must be between 1 and 128")
		}
	}
	// A separate key, so codes are never hashed with the JWT signing key.
	if v.key, err = hkdf.Key(sha256.New, []byte(secret), nil, "goauth verification v1", 32); err != nil {
		return nil, err
	}
	if v.emails, err = loadEmailTemplates(o.EmailTemplates); err != nil {
		return nil, err
	}
	return v, nil
}

// --- Codes ---------------------------------------------------------------------

// randomCode draws length characters uniformly from charset with
// crypto/rand, using rejection sampling so no character is more likely.
func randomCode(length int, charset string) string {
	n := len(charset)
	limit := 256 - 256%n // largest multiple of n that fits in a byte
	out := make([]byte, 0, length)
	buf := make([]byte, length*2)
	for len(out) < length {
		_, _ = rand.Read(buf) // never fails since Go 1.24
		for _, b := range buf {
			if int(b) < limit {
				out = append(out, charset[int(b)%n])
				if len(out) == length {
					break
				}
			}
		}
	}
	return string(out)
}

// normalizeCode trims what users typically add when copying a code and
// folds case when the charset has no lower-case letters.
func normalizeCode(code, charset string) string {
	code = strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\t' {
			return -1
		}
		return r
	}, code)
	if strings.ToUpper(charset) == charset {
		code = strings.ToUpper(code)
	}
	return code
}

func (v *verification) hash(parts ...string) string {
	m := hmac.New(sha256.New, v.key)
	for _, p := range parts {
		m.Write([]byte(p))
		m.Write([]byte{0})
	}
	return hex.EncodeToString(m.Sum(nil))
}

func (v *verification) codeHash(kind VerificationKind, identifier, code string) string {
	return v.hash("code", string(kind), identifier, code)
}

func (v *verification) tokenHash(kind VerificationKind, token string) string {
	return v.hash("link", string(kind), token)
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// normalizeEmail lower-cases and validates an email address. It returns ""
// for anything that is not a single plain address.
func normalizeEmail(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 254 || strings.ContainsAny(raw, " <>,;\"") {
		return ""
	}
	addr, err := mail.ParseAddress(raw)
	if err != nil || addr.Address != raw || !strings.Contains(raw[strings.LastIndexByte(raw, '@')+1:], ".") {
		return ""
	}
	return strings.ToLower(raw)
}
