package goauth

import (
	"context"
	"errors"
	"net/url"
	"time"
	"uuid"

	"gorm.io/gorm"
)

// Errors returned to clients by the verification endpoints. They never say
// whether an account exists.
var (
	ErrVerificationInvalid = errors.New("that code or link is invalid or has expired")
)

// MigrateVerificationTokens creates or updates the verification table with
// GORM's AutoMigrate. The model uses only portable column types, so this
// works on every GORM driver. You can also create the table yourself; see
// the database setup guide.
func (a *Authorization) MigrateVerificationTokens(ctx context.Context) error {
	if a == nil || a.db == nil {
		return ErrNotInitialized
	}
	return a.db.WithContext(ctx).Table(a.verify.table).AutoMigrate(&VerificationToken{})
}

func (a *Authorization) verificationTable(ctx context.Context) *gorm.DB {
	return a.db.WithContext(ctx).Table(a.verify.table)
}

// challengeID picks the verification id a "send me a code" request answers
// with. While a code for (kind, email) is still live and inside the resend
// cooldown, it is that code's id, and no new email is sent (fresh=false).
// Otherwise it is a new random id that the background job uses for the row
// it creates, if the account exists. Either way the caller gets one opaque
// id, so the answer looks the same for unknown emails.
func (a *Authorization) challengeID(ctx context.Context, f *verifyFeature, email string) (id string, fresh bool, err error) {
	if f.code.ResendAfter > 0 {
		now := time.Now().UTC()
		var live VerificationToken
		err := a.verificationTable(ctx).
			Select("id").
			Where("kind = ? AND identifier = ? AND consumed_at IS NULL AND created_at > ? AND expires_at > ?",
				f.kind, email, now.Add(-f.code.ResendAfter), now).
			Order("created_at DESC").
			Take(&live).Error
		if err == nil && live.ID != "" {
			return live.ID, false, nil
		}
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return "", false, err
		}
	}
	return uuid.NewV4().String(), true, nil
}

// issueVerification stores a new code and/or link for (kind, email) under
// the given id and returns the message to send. Previous unused codes for
// the same pair are retired.
func (a *Authorization) issueVerification(ctx context.Context, f *verifyFeature, id, email, userID, origin string) (*VerificationMessage, error) {
	now := time.Now().UTC()
	// One live code per (kind, email): sending a new one retires the old.
	if err := a.verificationTable(ctx).
		Where("kind = ? AND identifier = ? AND consumed_at IS NULL", f.kind, email).
		Update("consumed_at", now).Error; err != nil {
		return nil, err
	}

	row := VerificationToken{
		ID:         id,
		Kind:       f.kind,
		Identifier: email,
		UserID:     userID,
		ExpiresAt:  now.Add(f.code.TTL),
		CreatedAt:  now,
	}
	msg := &VerificationMessage{Kind: f.kind, To: email, UserID: userID, ExpiresAt: row.ExpiresAt}
	if f.code.Delivery.hasCode() {
		msg.Code = randomCode(f.code.Length, f.code.Charset)
		row.CodeHash = a.verify.codeHash(f.kind, email, normalizeCode(msg.Code, f.code.Charset))
	}
	if f.code.Delivery.hasLink() {
		token := randomString(32)
		row.TokenHash = a.verify.tokenHash(f.kind, token)
		// The link names the verification by id, never by email.
		msg.Link = origin + a.pagePath(pageForKind(f.kind)) + "?" + url.Values{fieldVID: {id}, fieldToken: {token}}.Encode()
	}
	if err := a.verificationTable(ctx).Create(&row).Error; err != nil {
		return nil, err
	}
	return msg, nil
}

// verifyInput identifies a verification and carries the secret that proves
// it: the id (vid) or, for API clients, the email; and a code or a token.
type verifyInput struct {
	vid, email, code, token string
}

// identifierForVID returns the email of a verification row, in any state,
// so "resend" can work from the id alone.
func (a *Authorization) identifierForVID(ctx context.Context, f *verifyFeature, vid string) (string, error) {
	if !validVID(vid) {
		return "", ErrVerificationInvalid
	}
	var row VerificationToken
	err := a.verificationTable(ctx).Select("identifier").Where("id = ? AND kind = ?", vid, f.kind).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", ErrVerificationInvalid
	}
	return row.Identifier, err
}

func validVID(vid string) bool {
	_, err := uuid.Parse(vid)
	return err == nil
}

// findLive loads the unused, unexpired verification the input points at.
func (a *Authorization) findLive(ctx context.Context, f *verifyFeature, in verifyInput) (*VerificationToken, error) {
	var row VerificationToken
	q := a.verificationTable(ctx).Where("kind = ? AND consumed_at IS NULL", f.kind)
	switch {
	case in.vid != "":
		if !validVID(in.vid) {
			return nil, ErrVerificationInvalid
		}
		q = q.Where("id = ?", in.vid)
	case in.token != "":
		q = q.Where("token_hash = ?", a.verify.tokenHash(f.kind, in.token))
	case in.code != "" && in.email != "":
		q = q.Where("identifier = ?", in.email).Order("created_at DESC")
	default:
		return nil, ErrVerificationInvalid
	}
	if err := q.Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrVerificationInvalid
		}
		return nil, err
	}
	if time.Now().UTC().After(row.ExpiresAt.UTC()) || (in.email != "" && row.Identifier != in.email) {
		return nil, ErrVerificationInvalid
	}
	return &row, nil
}

// checkSecret verifies the token or code against a live row. Wrong codes
// count against MaxAttempts; once that is reached the code stops working
// even if the right one is entered later.
func (a *Authorization) checkSecret(ctx context.Context, f *verifyFeature, row *VerificationToken, in verifyInput) error {
	if in.token != "" {
		if row.TokenHash == "" || !constantTimeEqual(a.verify.tokenHash(f.kind, in.token), row.TokenHash) {
			return ErrVerificationInvalid
		}
		return nil
	}
	if in.code == "" || row.CodeHash == "" || row.Attempts >= f.code.MaxAttempts {
		return ErrVerificationInvalid
	}
	want := a.verify.codeHash(f.kind, row.Identifier, normalizeCode(in.code, f.code.Charset))
	if !constantTimeEqual(want, row.CodeHash) {
		if err := a.verificationTable(ctx).
			Where("id = ?", row.ID).
			Update("attempts", gorm.Expr("attempts + ?", 1)).Error; err != nil {
			return err
		}
		return ErrVerificationInvalid
	}
	return nil
}

// consumeVerification checks the code or token and marks the verification
// used. Single use, even under concurrent requests: only the update that
// still sees consumed_at IS NULL wins.
func (a *Authorization) consumeVerification(ctx context.Context, f *verifyFeature, in verifyInput) (*VerificationToken, error) {
	row, err := a.findLive(ctx, f, in)
	if err != nil {
		return nil, err
	}
	if err := a.checkSecret(ctx, f, row, in); err != nil {
		return nil, err
	}
	res := a.verificationTable(ctx).
		Where("id = ? AND consumed_at IS NULL", row.ID).
		Update("consumed_at", time.Now().UTC())
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected != 1 {
		return nil, ErrVerificationInvalid
	}
	return row, nil
}

// exchangeCodeForToken checks a code without finishing the verification:
// the code is used up and replaced by a fresh one-time token, which the
// next step (choosing a new password) presents. Only one exchange can win.
func (a *Authorization) exchangeCodeForToken(ctx context.Context, f *verifyFeature, in verifyInput) (*VerificationToken, string, error) {
	in.token = "" // a code is required here
	row, err := a.findLive(ctx, f, in)
	if err != nil {
		return nil, "", err
	}
	if err := a.checkSecret(ctx, f, row, in); err != nil {
		return nil, "", err
	}
	token := randomString(32)
	res := a.verificationTable(ctx).
		Where("id = ? AND consumed_at IS NULL AND code_hash = ?", row.ID, row.CodeHash).
		Updates(map[string]any{"token_hash": a.verify.tokenHash(f.kind, token), "code_hash": ""})
	if res.Error != nil {
		return nil, "", res.Error
	}
	if res.RowsAffected != 1 {
		return nil, "", ErrVerificationInvalid
	}
	return row, token, nil
}

// revokeUserSessions signs a user out everywhere.
func (a *Authorization) revokeUserSessions(ctx context.Context, userID string) error {
	err := a.db.WithContext(ctx).Table(a.sessionsTable()).
		Where("user_id = ? AND is_deleted = ?", userID, false).
		Updates(map[string]any{"is_deleted": true, "updated_at": time.Now().UTC()}).Error
	// Redis copies need no cleanup: every lookup re-checks the database,
	// which now reports these sessions as signed out.
	return err
}

// pageForKind is the page a verification link opens. Links are only sent
// while that page is on (see New).
func pageForKind(kind VerificationKind) string {
	switch kind {
	case KindPasswordReset:
		return pageForgot
	case KindEmailConfirmation:
		return pageVerify
	default:
		return pageOTP
	}
}
