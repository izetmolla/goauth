package goauth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// sendVerification answers a "send me a code" request: it picks the
// verification id the client continues with and, unless a live code is still
// inside its resend cooldown, emails a new one in the background. The id
// comes back the same way whether or not the account exists.
func (a *Authorization) sendVerification(r *http.Request, f *verifyFeature, email string, onlyUnverified bool) (string, error) {
	id, fresh, err := a.challengeID(r.Context(), f, email)
	if err != nil {
		return "", err
	}
	if fresh {
		a.dispatchVerification(r, f, id, email, onlyUnverified)
	}
	return id, nil
}

// dispatchVerification looks the user up, issues a code/link under id and
// sends the email, all in the background. The HTTP response is identical
// whether or not the account exists, and its timing does not depend on the
// database or the mail provider. onlyUnverified skips users whose email is
// already confirmed.
func (a *Authorization) dispatchVerification(r *http.Request, f *verifyFeature, id, email string, onlyUnverified bool) {
	origin, _, err := a.origin(r)
	if err != nil {
		a.verifyError(r.Context(), f.kind, email, err)
		return
	}
	parent := context.WithoutCancel(r.Context())
	go func() {
		ctx, cancel := context.WithTimeout(parent, 30*time.Second)
		defer cancel()
		user, err := a.verify.opts.FindUser(ctx, email)
		if err != nil {
			a.verifyError(ctx, f.kind, email, err)
			return
		}
		if user == nil || user.ID == "" || (onlyUnverified && user.EmailVerified) {
			return
		}
		msg, err := a.issueVerification(ctx, f, id, email, user.ID, origin)
		if err != nil {
			a.verifyError(ctx, f.kind, email, err)
			return
		}
		if err := a.renderEmail(msg); err != nil {
			a.verifyError(ctx, f.kind, email, err)
			return
		}
		if err := a.verify.opts.Send(ctx, msg); err != nil {
			a.verifyError(ctx, f.kind, email, err)
		}
	}()
}

func (a *Authorization) verifyError(ctx context.Context, kind VerificationKind, email string, err error) {
	if err != nil && a.verify.opts.OnError != nil {
		a.verify.opts.OnError(ctx, kind, email, err)
	}
}

// codeExtras is what the client needs to render the next step.
func (a *Authorization) codeExtras(f *verifyFeature) Map {
	return Map{
		"resend_after": int(max(f.code.ResendAfter, 0) / time.Second),
		"expires_in":   int(max(f.code.TTL, 0) / time.Second),
		"code_length":  f.code.Length,
		"has_code":     f.code.Delivery.hasCode(),
		"has_link":     f.code.Delivery.hasLink(),
	}
}

// featureOn reports whether a verification feature is enabled, answering
// 404 when it is not.
func (a *Authorization) featureOn(w http.ResponseWriter, f func(*verification) *verifyFeature) (*verifyFeature, bool) {
	if a == nil || a.verify == nil {
		notFound(w)
		return nil, false
	}
	feat := f(a.verify)
	if !feat.enabled {
		notFound(w)
		return nil, false
	}
	return feat, true
}

var (
	emailField    = CredentialField{Name: inputEmail, Type: inputEmail}
	vidField      = CredentialField{Name: fieldVID}
	codeField     = CredentialField{Name: stepCode}
	tokenField    = CredentialField{Name: fieldToken}
	passwordField = CredentialField{Name: inputPassword, Type: inputPassword}
	confirmField  = CredentialField{Name: fieldConfirm, Type: inputPassword}
)

func verifyInputFrom(in formInput) verifyInput {
	return verifyInput{
		vid:   in.values[fieldVID],
		email: normalizeEmail(in.values[inputEmail]),
		code:  in.values[stepCode],
		token: in.values[fieldToken],
	}
}

// startVerification is the shared "send me a code" step. The email comes
// from the form, or, for "resend", from the verification id.
func (a *Authorization) startVerification(w http.ResponseWriter, r *http.Request, f *verifyFeature, page, sentMessage string, onlyUnverified bool) {
	in, ok := a.postForm(w, r, page, []CredentialField{emailField, vidField})
	if !ok {
		return
	}
	step := stepSent
	if f.code.Delivery.hasCode() {
		step = stepCode
	}
	email := normalizeEmail(in.values[inputEmail])
	if email == "" && in.values[fieldVID] != "" {
		var err error
		email, err = a.identifierForVID(r.Context(), f, in.values[fieldVID])
		if errors.Is(err, ErrVerificationInvalid) {
			// Unknown id (for example an email without an account): answer
			// exactly like a resend inside the cooldown.
			a.stepResponse(w, r, page, step, in.values[fieldVID], sentMessage, a.codeExtras(f))
			return
		}
		if err != nil {
			a.failure(w, r, page, http.StatusInternalServerError, codeServerError, msgSomethingWrong, "")
			return
		}
	}
	if email == "" {
		a.failure(w, r, page, http.StatusBadRequest, codeInvalidEmail, "Enter a valid email address.", inputEmail)
		return
	}
	vid, err := a.sendVerification(r, f, email, onlyUnverified)
	if err != nil {
		a.failure(w, r, page, http.StatusInternalServerError, codeServerError, msgSomethingWrong, "")
		return
	}
	a.stepResponse(w, r, page, step, vid, sentMessage, a.codeExtras(f))
}

// verificationFailed writes the error for a failed code or token check.
func (a *Authorization) verificationFailed(w http.ResponseWriter, r *http.Request, page string, err error) {
	switch {
	case errors.Is(err, ErrVerificationExpired):
		a.failure(w, r, page, http.StatusBadRequest, codeCodeExpired,
			"That code or link has expired. Request a new one and try again.", stepCode)
	case errors.Is(err, ErrVerificationUsed):
		a.failure(w, r, page, http.StatusBadRequest, codeCodeUsed,
			"That code or link has already been used. Request a new one if you still need to reset your password.", stepCode)
	case errors.Is(err, ErrVerificationInvalid):
		a.failure(w, r, page, http.StatusBadRequest, codeInvalidCode,
			"That code is invalid or has expired. Request a new one and try again.", stepCode)
	default:
		a.failure(w, r, page, http.StatusInternalServerError, codeServerError, msgSomethingWrong, "")
	}
}

// checkVerification is the shared "here is my code / link" step. It writes
// the error response and returns nil on failure.
func (a *Authorization) checkVerification(w http.ResponseWriter, r *http.Request, f *verifyFeature, page string, in formInput) *VerificationToken {
	row, err := a.consumeVerification(r.Context(), f, verifyInputFrom(in))
	if err != nil {
		a.verificationFailed(w, r, page, err)
		return nil
	}
	return row
}

// --- Password reset -------------------------------------------------------------

// HandleForgotPassword implements POST {base}/password/forgot: it emails a
// reset code or link when the account exists, and answers the same either
// way. The response carries the verification id (vid) for the next steps.
func (a *Authorization) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	f, ok := a.featureOn(w, func(v *verification) *verifyFeature { return &v.reset })
	if !ok {
		return
	}
	a.startVerification(w, r, f, pageForgot, "If an account exists for that email, we've sent password reset instructions.", false)
}

// HandleResetVerifyCode implements POST {base}/password/verify-code: it
// checks the emailed code and, if it is right, answers with a one-time
// token for choosing the new password (step "reset"). The code cannot be
// used again.
func (a *Authorization) HandleResetVerifyCode(w http.ResponseWriter, r *http.Request) {
	f, ok := a.featureOn(w, func(v *verification) *verifyFeature { return &v.reset })
	if !ok {
		return
	}
	in, ok := a.postForm(w, r, pageForgot, []CredentialField{vidField, emailField, codeField})
	if !ok {
		return
	}
	row, token, err := a.exchangeCodeForToken(r.Context(), f, verifyInputFrom(in))
	if err != nil {
		a.verificationFailed(w, r, pageForgot, err)
		return
	}
	a.stepResponse(w, r, pageForgot, stepReset, row.ID, "Code confirmed. Choose a new password.", Map{fieldToken: token})
}

// HandleResetCheck implements POST {base}/password/check: it verifies that
// a reset link token (or code) is still live without consuming it, so a
// SPA can refuse to show the new-password form for expired or already-used
// links. Email scanners that only GET the landing URL never hit this.
func (a *Authorization) HandleResetCheck(w http.ResponseWriter, r *http.Request) {
	f, ok := a.featureOn(w, func(v *verification) *verifyFeature { return &v.reset })
	if !ok {
		return
	}
	in, ok := a.postForm(w, r, pageForgot, []CredentialField{vidField, emailField, codeField, tokenField})
	if !ok {
		return
	}
	vin := verifyInputFrom(in)
	row, err := a.findLive(r.Context(), f, vin)
	if err != nil {
		a.verificationFailed(w, r, pageForgot, err)
		return
	}
	if err := a.checkSecret(r.Context(), f, row, vin); err != nil {
		a.verificationFailed(w, r, pageForgot, err)
		return
	}
	left := max(int(time.Until(row.ExpiresAt.UTC()).Seconds()), 0)
	a.stepResponse(w, r, pageForgot, stepReset, row.ID, "Reset link is still valid.", Map{
		"expires_in": left,
		"expires_at": row.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// HandleResetPassword implements POST {base}/password/reset: it checks the
// token (from the reset link or from HandleResetVerifyCode) or the code,
// stores the new password with SetPassword, signs the user out everywhere
// (unless PasswordReset.KeepSessions), then signs them in with a fresh
// session (JSON clients get type=sign_in; HTML gets the callback page).
// When password_confirm is sent it must match password.
func (a *Authorization) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	f, ok := a.featureOn(w, func(v *verification) *verifyFeature { return &v.reset })
	if !ok {
		return
	}
	in, ok := a.postForm(w, r, pageForgot, []CredentialField{vidField, emailField, codeField, tokenField, passwordField, confirmField})
	if !ok {
		return
	}
	opts := a.verify.opts.PasswordReset
	pw := in.values[inputPassword]
	if len([]rune(pw)) < opts.MinPasswordLength {
		a.failure(w, r, pageForgot, http.StatusBadRequest, codeWeakPassword, "Use at least "+strconv.Itoa(opts.MinPasswordLength)+" characters.", inputPassword)
		return
	}
	if confirm, sent := in.values[fieldConfirm]; sent && confirm != "" && confirm != pw {
		a.failure(w, r, pageForgot, http.StatusBadRequest, codePasswordMismatch, "Passwords don't match.", fieldConfirm)
		return
	}
	row := a.checkVerification(w, r, f, pageForgot, in)
	if row == nil {
		return
	}
	ctx := r.Context()
	if err := a.verify.opts.SetPassword(ctx, row.UserID, pw); err != nil {
		if ce, ok := errors.AsType[*CredentialsError](err); ok {
			a.failure(w, r, pageForgot, http.StatusBadRequest, codeWeakPassword, ce.Message, inputPassword)
			return
		}
		a.failure(w, r, pageForgot, http.StatusInternalServerError, codeServerError, msgSomethingWrong, "")
		return
	}
	// Burn any other live reset emails for this address so an older link
	// cannot change the password again after this one succeeded.
	if err := a.consumeSiblingVerifications(ctx, f, row.Identifier, row.ID); err != nil {
		a.verifyError(ctx, f.kind, row.Identifier, err)
	}
	if !opts.KeepSessions {
		if err := a.revokeUserSessions(ctx, row.UserID); err != nil {
			a.verifyError(ctx, f.kind, row.Identifier, err)
		}
	}
	// Receiving the email proves the address is theirs.
	if mv := a.verify.opts.MarkVerified; mv != nil {
		_ = mv(ctx, row.UserID)
	}
	// Resetting the password proves control of the email, so a lockout
	// left by earlier wrong passwords no longer applies.
	a.clearLoginFailuresFor(ctx, normalizeEmail(row.Identifier))
	user := Map{"id": row.UserID}
	if row.Identifier != "" {
		user[inputEmail] = row.Identifier
	}
	a.finishSignIn(w, r, pageForgot, row.UserID, user, "password_reset", in.redirect)
}

// --- One-time code sign-in ------------------------------------------------------

// HandleOTPSend implements POST {base}/otp/send.
func (a *Authorization) HandleOTPSend(w http.ResponseWriter, r *http.Request) {
	f, ok := a.featureOn(w, func(v *verification) *verifyFeature { return &v.otp })
	if !ok {
		return
	}
	a.startVerification(w, r, f, pageOTP, "If an account exists for that email, we've sent a sign-in code.", false)
}

// HandleOTPVerify implements POST {base}/otp/verify: it checks the code (or
// magic-link token) and signs the user in.
func (a *Authorization) HandleOTPVerify(w http.ResponseWriter, r *http.Request) {
	f, ok := a.featureOn(w, func(v *verification) *verifyFeature { return &v.otp })
	if !ok {
		return
	}
	in, ok := a.postForm(w, r, pageOTP, []CredentialField{vidField, emailField, codeField, tokenField})
	if !ok {
		return
	}
	row := a.checkVerification(w, r, f, pageOTP, in)
	if row == nil {
		return
	}
	if mv := a.verify.opts.MarkVerified; mv != nil {
		_ = mv(r.Context(), row.UserID)
	}
	a.finishSignIn(w, r, pageOTP, row.UserID, Map{"id": row.UserID, inputEmail: row.Identifier}, "otp", in.redirect)
}

// --- Email confirmation ---------------------------------------------------------

// HandleVerifyEmailSend implements POST {base}/verify-email/send: it
// (re)sends a confirmation email to an unconfirmed account.
func (a *Authorization) HandleVerifyEmailSend(w http.ResponseWriter, r *http.Request) {
	f, ok := a.featureOn(w, func(v *verification) *verifyFeature { return &v.confirm })
	if !ok {
		return
	}
	a.startVerification(w, r, f, pageVerify, "If that email needs confirming, we've sent a new confirmation email.", true)
}

// HandleVerifyEmail implements POST {base}/verify-email: it checks the code
// (or link token) and calls MarkVerified.
func (a *Authorization) HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	f, ok := a.featureOn(w, func(v *verification) *verifyFeature { return &v.confirm })
	if !ok {
		return
	}
	in, ok := a.postForm(w, r, pageVerify, []CredentialField{vidField, emailField, codeField, tokenField})
	if !ok {
		return
	}
	row := a.checkVerification(w, r, f, pageVerify, in)
	if row == nil {
		return
	}
	if err := a.verify.opts.MarkVerified(r.Context(), row.UserID); err != nil {
		a.failure(w, r, pageVerify, http.StatusInternalServerError, codeServerError, msgSomethingWrong, "")
		return
	}
	a.stepResponse(w, r, pageVerify, stepDone, "", "Your email is confirmed. You can sign in now.", nil)
}
