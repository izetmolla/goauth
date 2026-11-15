package goauth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// dispatchVerification looks the user up, issues a code/link and sends the
// email, all in the background. The HTTP response is identical whether or
// not the account exists, and its timing does not depend on the database
// or the mail provider. onlyUnverified skips users whose email is already
// confirmed.
func (a *Authorization) dispatchVerification(r *http.Request, f *verifyFeature, email string, onlyUnverified bool) {
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
		msg, err := a.issueVerification(ctx, f, email, user.ID, origin)
		if err != nil || msg == nil { // msg == nil: resend cooldown
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
	codeField     = CredentialField{Name: stepCode}
	tokenField    = CredentialField{Name: fieldToken}
	passwordField = CredentialField{Name: inputPassword, Type: inputPassword}
)

// startVerification is the shared "send me a code" step.
func (a *Authorization) startVerification(w http.ResponseWriter, r *http.Request, f *verifyFeature, page, sentMessage string, onlyUnverified bool) {
	in, ok := a.postForm(w, r, page, []CredentialField{emailField})
	if !ok {
		return
	}
	email := normalizeEmail(in.values[inputEmail])
	if email == "" {
		a.failure(w, r, page, http.StatusBadRequest, codeInvalidEmail, "Enter a valid email address.", inputEmail)
		return
	}
	a.dispatchVerification(r, f, email, onlyUnverified)
	step := stepSent
	if f.code.Delivery.hasCode() {
		step = stepCode
	}
	a.stepResponse(w, r, page, step, email, sentMessage, a.codeExtras(f))
}

// checkVerification is the shared "here is my code / link" step. It writes
// the error response and returns nil on failure.
func (a *Authorization) checkVerification(w http.ResponseWriter, r *http.Request, f *verifyFeature, page string, in formInput) *VerificationToken {
	email := normalizeEmail(in.values[inputEmail])
	row, err := a.consumeVerification(r.Context(), f, email, in.values[stepCode], in.values[fieldToken])
	switch {
	case errors.Is(err, ErrVerificationInvalid):
		a.failure(w, r, page, http.StatusBadRequest, codeInvalidCode, "That code is invalid or has expired. Request a new one and try again.", stepCode)
		return nil
	case err != nil:
		a.failure(w, r, page, http.StatusInternalServerError, codeServerError, msgSomethingWrong, "")
		return nil
	}
	return row
}

// --- Password reset -------------------------------------------------------------

// HandleForgotPassword implements POST {base}/password/forgot: it emails a
// reset code or link when the account exists, and answers the same either
// way.
func (a *Authorization) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	f, ok := a.featureOn(w, func(v *verification) *verifyFeature { return &v.reset })
	if !ok {
		return
	}
	a.startVerification(w, r, f, pageForgot, "If an account exists for that email, we've sent password reset instructions.", false)
}

// HandleResetPassword implements POST {base}/password/reset: it checks the
// code (or link token), stores the new password with SetPassword and signs
// the user out everywhere (unless PasswordReset.KeepSessions).
func (a *Authorization) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	f, ok := a.featureOn(w, func(v *verification) *verifyFeature { return &v.reset })
	if !ok {
		return
	}
	in, ok := a.postForm(w, r, pageForgot, []CredentialField{emailField, codeField, tokenField, passwordField})
	if !ok {
		return
	}
	opts := a.verify.opts.PasswordReset
	pw := in.values[inputPassword]
	if len([]rune(pw)) < opts.MinPasswordLength {
		a.failure(w, r, pageForgot, http.StatusBadRequest, codeWeakPassword, "Use at least "+strconv.Itoa(opts.MinPasswordLength)+" characters.", inputPassword)
		return
	}
	row := a.checkVerification(w, r, f, pageForgot, in)
	if row == nil {
		return
	}
	ctx := r.Context()
	if err := a.verify.opts.SetPassword(ctx, row.UserID, pw); err != nil {
		var ce *CredentialsError
		if errors.As(err, &ce) {
			a.failure(w, r, pageForgot, http.StatusBadRequest, codeWeakPassword, ce.Message, inputPassword)
			return
		}
		a.failure(w, r, pageForgot, http.StatusInternalServerError, codeServerError, msgSomethingWrong, "")
		return
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
	a.stepResponse(w, r, pageForgot, stepDone, row.Identifier, "Your password has been updated. You can sign in now.", nil)
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
	in, ok := a.postForm(w, r, pageOTP, []CredentialField{emailField, codeField, tokenField})
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
	in, ok := a.postForm(w, r, pageVerify, []CredentialField{emailField, codeField, tokenField})
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
	a.stepResponse(w, r, pageVerify, stepDone, row.Identifier, "Your email is confirmed. You can sign in now.", nil)
}
