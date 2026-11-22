package goauth

import (
	"cmp"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// HandleTOTPStatus implements GET {base}/mfa/totp/status.
func (a *Authorization) HandleTOTPStatus(w http.ResponseWriter, r *http.Request) {
	if !a.totpEnabled() {
		notFound(w)
		return
	}
	userID, ok := a.requireSessionUser(w, r)
	if !ok {
		return
	}
	row, err := a.loadTotpFactor(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{"code": codeServerError, "message": msgSomethingWrong})
		return
	}
	enabled, confirmed := false, false
	if row != nil {
		enabled = row.Enabled
		confirmed = row.ConfirmedAt != nil
	}
	writeJSON(w, http.StatusOK, Map{"enabled": enabled, "confirmed": confirmed})
}

// HandleTOTPEnrollBegin implements POST {base}/mfa/totp/enroll/begin.
// It creates a pending (disabled) factor and returns the otpauth URI + secret.
func (a *Authorization) HandleTOTPEnrollBegin(w http.ResponseWriter, r *http.Request) {
	if !a.totpEnabled() {
		notFound(w)
		return
	}
	userID, ok := a.requireSessionUser(w, r)
	if !ok {
		return
	}
	in, ok := a.postForm(w, r, "", []CredentialField{
		{Name: inputEmail, Type: inputEmail},
		{Name: "account", Type: inputText},
	})
	if !ok {
		return
	}
	row, err := a.loadTotpFactor(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{"code": codeServerError, "message": msgSomethingWrong})
		return
	}
	if row != nil && row.Enabled {
		writeJSON(w, http.StatusConflict, Map{"code": codeMFAAlreadyOn, "message": "Authenticator MFA is already enabled"})
		return
	}
	accountName := strings.TrimSpace(in.values["account"])
	if accountName == "" {
		accountName = strings.TrimSpace(in.values[inputEmail])
	}
	if accountName == "" {
		accountName = userID
	}
	key, err := a.totp.generateKey(accountName)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{"code": codeServerError, "message": msgSomethingWrong})
		return
	}
	enc, err := a.totp.encryptSecret([]byte(key.Secret()))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{"code": codeServerError, "message": msgSomethingWrong})
		return
	}
	if err := a.upsertPendingTOTP(r.Context(), userID, enc); err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{"code": codeServerError, "message": msgSomethingWrong})
		return
	}
	writeJSON(w, http.StatusOK, Map{
		"secret":      key.Secret(),
		"otpauth_url": key.URL(),
		"issuer":      a.totp.issuer,
		"account":     accountName,
	})
}

// HandleTOTPEnrollConfirm implements POST {base}/mfa/totp/enroll/confirm.
func (a *Authorization) HandleTOTPEnrollConfirm(w http.ResponseWriter, r *http.Request) {
	if !a.totpEnabled() {
		notFound(w)
		return
	}
	userID, ok := a.requireSessionUser(w, r)
	if !ok {
		return
	}
	in, ok := a.postForm(w, r, "", []CredentialField{
		{Name: "code", Type: inputText, Placeholder: "123456"},
	})
	if !ok {
		return
	}
	code := strings.TrimSpace(in.values["code"])
	if code == "" {
		writeJSON(w, http.StatusBadRequest, Map{"code": codeBadRequest, "message": "Code is required", "field": "code"})
		return
	}
	row, err := a.loadTotpFactor(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{"code": codeServerError, "message": msgSomethingWrong})
		return
	}
	if row == nil || len(row.SecretEnc) == 0 {
		writeJSON(w, http.StatusBadRequest, Map{"code": codeBadRequest, "message": "Start enrollment first"})
		return
	}
	if row.Enabled {
		writeJSON(w, http.StatusConflict, Map{"code": codeMFAAlreadyOn, "message": "Authenticator MFA is already enabled"})
		return
	}
	secret, err := a.totp.decryptSecret(row.SecretEnc)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{"code": codeServerError, "message": msgSomethingWrong})
		return
	}
	if a.totp.limiter.blocked(userID) {
		writeMFATooMany(w)
		return
	}
	if !a.totp.validateTOTP(string(secret), code) {
		a.totp.limiter.fail(userID)
		writeInvalidTOTP(w)
		return
	}
	a.totp.limiter.succeed(userID)
	codes, err := generateBackupCodes(backupCodeCount)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{"code": codeServerError, "message": msgSomethingWrong})
		return
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = a.totp.hashBackup(c)
	}
	if err := a.confirmTOTP(r.Context(), userID, row.SecretEnc, hashes); err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{"code": codeServerError, "message": msgSomethingWrong})
		return
	}
	writeJSON(w, http.StatusOK, Map{
		"enabled":      true,
		"backup_codes": codes,
		"message":      "Authenticator MFA enabled. Store these backup codes somewhere safe.",
	})
}

// HandleTOTPDisable implements POST {base}/mfa/totp/disable.
func (a *Authorization) HandleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if !a.totpEnabled() {
		notFound(w)
		return
	}
	userID, ok := a.requireSessionUser(w, r)
	if !ok {
		return
	}
	in, ok := a.postForm(w, r, "", []CredentialField{
		{Name: "code", Type: inputText, Placeholder: "123456"},
	})
	if !ok {
		return
	}
	code := strings.TrimSpace(in.values["code"])
	if code == "" {
		writeJSON(w, http.StatusBadRequest, Map{"code": codeBadRequest, "message": "Code is required", "field": "code"})
		return
	}
	if err := a.checkTOTPCode(r.Context(), userID, code); err != nil {
		if errors.Is(err, errMFANotEnabled) {
			writeJSON(w, http.StatusBadRequest, Map{"code": codeMFANotEnabled, "message": "Authenticator MFA is not enabled"})
			return
		}
		if !writeMFAError(w, err) {
			return
		}
		writeInvalidTOTP(w)
		return
	}
	if err := a.disableTOTP(r.Context(), userID); err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{"code": codeServerError, "message": msgSomethingWrong})
		return
	}
	writeJSON(w, http.StatusOK, Map{"enabled": false, "message": "Authenticator MFA disabled"})
}

// HandleTOTPVerify implements POST {base}/mfa/totp/verify for the sign-in challenge.
func (a *Authorization) HandleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	if !a.totpEnabled() {
		notFound(w)
		return
	}
	in, ok := a.postForm(w, r, "", []CredentialField{
		{Name: "mfa_token", Type: inputText},
		{Name: "code", Type: inputText, Placeholder: "123456"},
	})
	if !ok {
		return
	}
	token := strings.TrimSpace(in.values["mfa_token"])
	code := strings.TrimSpace(in.values["code"])
	if token == "" || code == "" {
		writeJSON(w, http.StatusBadRequest, Map{"code": codeBadRequest, "message": "mfa_token and code are required"})
		return
	}
	ch, err := a.decodeMFAChallenge(token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, Map{"code": codeMFAInvalid, "message": "Invalid or expired MFA token"})
		return
	}
	if err := a.checkTOTPCode(r.Context(), ch.UserID, code); err != nil {
		if !writeMFAError(w, err) {
			return
		}
		writeInvalidTOTP(w)
		return
	}
	a.completeMFASignIn(w, r, ch)
}

func (a *Authorization) completeMFASignIn(w http.ResponseWriter, r *http.Request, ch mfaChallenge) {
	opts := []AuthorizeOptionsFunc{a.WithUserID(ch.UserID)}
	if ch.Account != nil {
		opts = append(opts, a.WithAccount(ch.Account))
	}
	opts = append(opts, a.SessionMetaFromRequest(r, ch.Method)...)
	tokens, sessionID, err := a.Authorize(opts...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{"code": codeServerError, "message": msgSomethingWrong})
		return
	}
	tokenFlow := isTokenFlow(r)
	if !tokenFlow {
		a.SetSessionIDCookie(w, r, sessionID)
		if a.keepRefreshTokenServerSide {
			tokens.RefreshToken = ""
		}
	}
	payload := Map{
		payloadType:    "sign_in",
		"message":      "Signed in. Redirecting…",
		"user":         Map{"id": ch.UserID},
		"tokens":       tokens,
		"session_id":   sessionID,
		"redirect_url": cmp.Or(ch.Redirect, a.defaultRedirect()),
	}
	if tokenFlow || wantsJSON(r) {
		writeJSON(w, http.StatusOK, payload)
		return
	}
	a.renderCallbackPage(w, payload)
}

// writeInvalidTOTP answers a wrong authenticator or backup code.
func writeInvalidTOTP(w http.ResponseWriter) {
	writeJSON(w, http.StatusUnauthorized, Map{"code": codeMFAInvalid, "message": "Invalid authenticator code", "field": "code"})
}

func writeMFATooMany(w http.ResponseWriter) {
	w.Header().Set("Retry-After", strconv.Itoa(int(mfaFailureWindow.Seconds())))
	writeJSON(w, http.StatusTooManyRequests, Map{"code": codeMFATooMany, "message": msgMFATooMany})
}

// writeMFAError writes the response for lockouts and server errors from
// checkTOTPCode. It returns true when err is a plain wrong code, which the
// caller reports itself.
func writeMFAError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, errMFAInvalid):
		return true
	case errors.Is(err, errMFATooMany):
		writeMFATooMany(w)
	default:
		writeJSON(w, http.StatusInternalServerError, Map{"code": codeServerError, "message": msgSomethingWrong})
	}
	return false
}

// requireSessionUser loads the signed-in WEB session user id.
func (a *Authorization) requireSessionUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	session, err := a.GetSession(r.Context(), a.GetSessionID(r))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, Map{"code": codeUnauthorized, "message": "Sign in required"})
		return "", false
	}
	if session.UserID == "" {
		writeJSON(w, http.StatusUnauthorized, Map{"code": codeUnauthorized, "message": "Sign in required"})
		return "", false
	}
	return session.UserID, true
}

// maybeChallengeMFA returns true when it wrote an MFA_REQUIRED response and
// the caller must not create a session yet.
func (a *Authorization) maybeChallengeMFA(w http.ResponseWriter, r *http.Request, page, userID, method, redirect string, account *Account, user Map) bool {
	if !a.totpEnabled() {
		return false
	}
	needed, err := a.userHasEnabledTOTP(r.Context(), userID)
	if err != nil {
		a.failure(w, r, page, http.StatusInternalServerError, codeServerError, msgSomethingWrong, "")
		return true
	}
	if !needed {
		return false
	}
	token, err := a.issueMFAChallenge(userID, method, redirect, account)
	if err != nil {
		a.failure(w, r, page, http.StatusInternalServerError, codeServerError, msgSomethingWrong, "")
		return true
	}
	payload := mfaRequiredPayload(token)
	if user != nil {
		payload["user"] = user
	}
	path := a.pagePath(page)
	if isTokenFlow(r) || wantsJSON(r) || path == "" {
		writeJSON(w, http.StatusUnauthorized, payload)
		return true
	}
	// Browser form posts: HTML callback with MFA_REQUIRED so the SPA can prompt.
	a.renderCallbackPage(w, payload)
	return true
}
