package goauth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// TotpFactor is one user's authenticator-app MFA factor, stored in the
// goauth-owned TOTP table. Secrets are encrypted at rest; backup codes are
// stored only as keyed hashes.
type TotpFactor struct {
	UserID       string `gorm:"primaryKey;size:64"`
	SecretEnc    []byte `gorm:"not null"` // AES-GCM blob (portable across GORM drivers)
	Enabled      bool   `gorm:"not null;default:false"`
	BackupHashes string `gorm:"type:text"` // JSON array of hex HMAC hashes
	ConfirmedAt  *time.Time
	DisabledAt   *time.Time
	CreatedAt    time.Time `gorm:"not null"`
	UpdatedAt    time.Time `gorm:"not null"`
}

// TableName is the default GORM table for TotpFactor rows
// (DefaultTablePrefix + "totp"). MigrateTOTP and runtime queries still honor
// Config.TablePrefix / MFA.TOTP.TableName.
func (TotpFactor) TableName() string {
	return DefaultTablePrefix + totpTableSuffix
}

// MigrateTOTP creates or updates the TOTP factor table with GORM AutoMigrate.
// Call it when MFA.TOTP.Enabled is true (or before enabling it in production).
func (a *Authorization) MigrateTOTP(ctx context.Context) error {
	if a == nil || a.db == nil {
		return ErrNotInitialized
	}
	if !a.totpEnabled() {
		return errors.New("MFA.TOTP is not enabled")
	}
	return a.db.WithContext(ctx).Table(a.totp.table).AutoMigrate(&TotpFactor{})
}

func (a *Authorization) totpTable(ctx context.Context) *gorm.DB {
	return a.db.WithContext(ctx).Table(a.totp.table)
}

func (a *Authorization) loadTotpFactor(ctx context.Context, userID string) (*TotpFactor, error) {
	var row TotpFactor
	err := a.totpTable(ctx).Where("user_id = ?", userID).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// userHasEnabledTOTP reports whether the user must complete a TOTP challenge
// before a session is created.
func (a *Authorization) userHasEnabledTOTP(ctx context.Context, userID string) (bool, error) {
	if !a.totpEnabled() || userID == "" {
		return false, nil
	}
	var n int64
	err := a.totpTable(ctx).Where("user_id = ? AND enabled = ?", userID, true).Count(&n).Error
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (m *totpMFA) encryptSecret(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.encKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func (m *totpMFA) decryptSecret(blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.encKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}

func (m *totpMFA) hashBackup(code string) string {
	mac := hmac.New(sha256.New, m.hashKey)
	mac.Write([]byte(strings.ToUpper(strings.TrimSpace(code))))
	return hex.EncodeToString(mac.Sum(nil))
}

// matchTOTPStep returns the time step (Unix time / Period) whose code equals
// code, searching Skew steps either side of now.
func (m *totpMFA) matchTOTPStep(secret, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	opts := totp.ValidateOpts{Period: m.period, Digits: otp.Digits(m.digits), Algorithm: otp.AlgorithmSHA1}
	period := int64(m.period)
	current := now.Unix() / period
	for off := -int64(m.skew); off <= int64(m.skew); off++ {
		step := current + off
		want, err := totp.GenerateCodeCustom(secret, time.Unix(step*period, 0).UTC(), opts)
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// validateTOTP reports whether code is valid now (within Skew).
func (m *totpMFA) validateTOTP(secret, code string) bool {
	ok, err := totp.ValidateCustom(strings.TrimSpace(code), secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    m.period,
		Skew:      m.skew,
		Digits:    otp.Digits(m.digits),
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && ok
}

func (m *totpMFA) generateKey(accountName string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      m.issuer,
		AccountName: accountName,
		Period:      m.period,
		Digits:      otp.Digits(m.digits),
		Algorithm:   otp.AlgorithmSHA1,
	})
}

func parseBackupHashes(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func encodeBackupHashes(hashes []string) (string, error) {
	if len(hashes) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(hashes)
	return string(b), err
}

func generateBackupCodes(n int) ([]string, error) {
	codes := make([]string, 0, n)
	for range n {
		b := make([]byte, backupCodeBytes)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		// Crockford-ish base32 without padding, uppercase.
		codes = append(codes, strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="))
	}
	return codes, nil
}

func (a *Authorization) upsertPendingTOTP(ctx context.Context, userID string, secretEnc []byte) error {
	now := time.Now().UTC()
	row := TotpFactor{
		UserID:       userID,
		SecretEnc:    secretEnc,
		Enabled:      false,
		BackupHashes: "[]",
		ConfirmedAt:  nil,
		DisabledAt:   nil,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	return a.totpTable(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"secret_enc", "enabled", "backup_hashes", "confirmed_at", "disabled_at", "updated_at"}),
	}).Create(&row).Error
}

func (a *Authorization) confirmTOTP(ctx context.Context, userID string, secretEnc []byte, backupHashes []string) error {
	raw, err := encodeBackupHashes(backupHashes)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	return a.totpTable(ctx).Where("user_id = ?", userID).Updates(map[string]any{
		"secret_enc":    secretEnc,
		"enabled":       true,
		"backup_hashes": raw,
		"confirmed_at":  now,
		"disabled_at":   nil,
		"updated_at":    now,
	}).Error
}

func (a *Authorization) disableTOTP(ctx context.Context, userID string) error {
	now := time.Now().UTC()
	return a.totpTable(ctx).Where("user_id = ?", userID).Updates(map[string]any{
		"enabled":       false,
		"backup_hashes": "[]",
		"disabled_at":   now,
		"updated_at":    now,
	}).Error
}

// consumeBackupCode verifies a backup code and removes it from the factor.
func (a *Authorization) consumeBackupCode(ctx context.Context, row *TotpFactor, code string) (bool, error) {
	hashes, err := parseBackupHashes(row.BackupHashes)
	if err != nil {
		return false, err
	}
	want := a.totp.hashBackup(code)
	idx := -1
	for i, h := range hashes {
		if subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false, nil
	}
	hashes = append(hashes[:idx], hashes[idx+1:]...)
	raw, err := encodeBackupHashes(hashes)
	if err != nil {
		return false, err
	}
	// Compare-and-swap on the previous value: two requests racing with the
	// same backup code must not both succeed.
	res := a.totpTable(ctx).
		Where("user_id = ? AND backup_hashes = ?", row.UserID, row.BackupHashes).
		Updates(map[string]any{
			"backup_hashes": raw,
			"updated_at":    time.Now().UTC(),
		})
	if res.Error != nil {
		return false, res.Error
	}
	if res.RowsAffected != 1 {
		return false, nil
	}
	row.BackupHashes = raw
	return true, nil
}

func (a *Authorization) verifyTOTPOrBackup(ctx context.Context, userID, code string) error {
	row, err := a.loadTotpFactor(ctx, userID)
	if err != nil {
		return err
	}
	if row == nil || !row.Enabled {
		return errMFANotEnabled
	}
	secret, err := a.totp.decryptSecret(row.SecretEnc)
	if err != nil {
		return err
	}
	if step, ok := a.totp.matchTOTPStep(string(secret), code, time.Now()); ok {
		// A code is valid for several periods; accept each step only once
		// (RFC 6238 section 5.2), so a captured code cannot be replayed.
		if !a.totp.limiter.useStep(userID, step) {
			return errMFAInvalid
		}
		return nil
	}
	ok, err := a.consumeBackupCode(ctx, row, code)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	return errMFAInvalid
}

// checkTOTPCode is verifyTOTPOrBackup behind the per-user failure cap.
func (a *Authorization) checkTOTPCode(ctx context.Context, userID, code string) error {
	if a.totp.limiter.blocked(userID) {
		return errMFATooMany
	}
	err := a.verifyTOTPOrBackup(ctx, userID, code)
	switch {
	case err == nil:
		a.totp.limiter.succeed(userID)
	case errors.Is(err, errMFAInvalid):
		a.totp.limiter.fail(userID)
	}
	return err
}

var (
	errMFATooMany    = errors.New("too many incorrect authenticator codes")
	errMFAInvalid    = errors.New("invalid authenticator code")
	errMFANotEnabled = errors.New("authenticator MFA is not enabled for this user")
)
