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

// issueVerification stores a new code and/or link for (kind, email) and
// returns the message to send. Previous unused codes for the same pair are
// invalidated. It returns (nil, nil) while the resend cooldown is running.
func (a *Authorization) issueVerification(ctx context.Context, f *verifyFeature, email, userID, origin string) (*VerificationMessage, error) {
	now := time.Now().UTC()
	if f.code.ResendAfter > 0 {
		var last VerificationToken
		err := a.verificationTable(ctx).
			Select("created_at").
			Where("kind = ? AND identifier = ?", f.kind, email).
			Order("created_at DESC").
			Take(&last).Error
		if err == nil && now.Sub(last.CreatedAt.UTC()) < f.code.ResendAfter {
			return nil, nil
		}
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}

	// One live code per (kind, email): sending a new one retires the old.
	if err := a.verificationTable(ctx).
		Where("kind = ? AND identifier = ? AND consumed_at IS NULL", f.kind, email).
		Update("consumed_at", now).Error; err != nil {
		return nil, err
	}

	row := VerificationToken{
		ID:         uuid.NewV4().String(),
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
		msg.Link = origin + linkPath(f.kind) + "?" + url.Values{inputEmail: {email}, fieldToken: {token}}.Encode()
	}
	if err := a.verificationTable(ctx).Create(&row).Error; err != nil {
		return nil, err
	}
	return msg, nil
}

// consumeVerification checks a code (or link token) for (kind, email) and
// marks it used. Wrong codes count against MaxAttempts; once that is
// reached the code stops working even if the right one is entered later.
func (a *Authorization) consumeVerification(ctx context.Context, f *verifyFeature, email, code, token string) (*VerificationToken, error) {
	var row VerificationToken
	q := a.verificationTable(ctx).Where("kind = ? AND consumed_at IS NULL", f.kind)
	switch {
	case token != "":
		q = q.Where("token_hash = ?", a.verify.tokenHash(f.kind, token))
	case code != "" && email != "":
		q = q.Where("identifier = ?", email).Order("created_at DESC")
	default:
		return nil, ErrVerificationInvalid
	}
	if err := q.Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrVerificationInvalid
		}
		return nil, err
	}
	now := time.Now().UTC()
	if now.After(row.ExpiresAt.UTC()) || (email != "" && row.Identifier != email) {
		return nil, ErrVerificationInvalid
	}
	if token == "" {
		if row.CodeHash == "" || row.Attempts >= f.code.MaxAttempts {
			return nil, ErrVerificationInvalid
		}
		want := a.verify.codeHash(f.kind, row.Identifier, normalizeCode(code, f.code.Charset))
		if !constantTimeEqual(want, row.CodeHash) {
			if err := a.verificationTable(ctx).
				Where("id = ?", row.ID).
				Update("attempts", gorm.Expr("attempts + ?", 1)).Error; err != nil {
				return nil, err
			}
			return nil, ErrVerificationInvalid
		}
	}
	// Single use, even under concurrent requests: only the update that
	// still sees consumed_at IS NULL wins.
	res := a.verificationTable(ctx).
		Where("id = ? AND consumed_at IS NULL", row.ID).
		Update("consumed_at", now)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected != 1 {
		return nil, ErrVerificationInvalid
	}
	return &row, nil
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

// linkPath is the page a verification link opens.
func linkPath(kind VerificationKind) string {
	switch kind {
	case KindPasswordReset:
		return DefaultBasePath + "/password/reset"
	case KindEmailConfirmation:
		return DefaultBasePath + "/verify-email"
	default:
		return DefaultBasePath + "/otp/verify"
	}
}
