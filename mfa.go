package goauth

import (
	"cmp"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"time"
)

const (
	defaultTOTPTable  = "goauth_totp"
	defaultTOTPIssuer = "App"
	defaultTOTPDigits = 6
	defaultTOTPPeriod = 30
	defaultTOTPSkew   = uint(1)

	mfaChallengeTTL = 5 * time.Minute
	backupCodeCount = 10
	backupCodeBytes = 5 // ~8 base32 chars

	codeMFARequired   = "MFA_REQUIRED"
	codeMFAInvalid    = "MFA_INVALID"
	codeMFANotEnabled = "MFA_NOT_ENABLED"
	codeMFAAlreadyOn  = "MFA_ALREADY_ENABLED"
)

// MFAOptions configures multi-factor authentication. The zero value leaves MFA off.
type MFAOptions struct {
	TOTP TOTPOptions
}

// TOTPOptions configures authenticator-app MFA (Google Authenticator, Microsoft
// Authenticator, and any other RFC 6238 TOTP client). Off by default.
type TOTPOptions struct {
	// Enabled turns on TOTP MFA routes and the sign-in challenge. Default false.
	Enabled bool
	// Issuer is shown in authenticator apps. Defaults to UI.AppName, then "App".
	Issuer string
	// TableName is the GORM table for TotpFactor rows. Default "goauth_totp".
	TableName string
	// Digits is the code length (6 or 8). Default 6.
	Digits int
	// Period is the time step in seconds. Default 30.
	Period uint
	// Skew is how many adjacent periods to accept. Default 1.
	Skew uint
}

// totpMFA is the resolved TOTP configuration after New().
type totpMFA struct {
	enabled bool
	issuer  string
	table   string
	digits  int
	period  uint
	skew    uint
	encKey  []byte // AES-256 key for secret encryption
	hashKey []byte // HMAC key for backup-code hashes
	limiter *mfaLimiter
}

func newTOTP(o TOTPOptions, jwtSecret, appName string) (*totpMFA, error) {
	if !o.Enabled {
		return &totpMFA{enabled: false}, nil
	}
	digits := o.Digits
	if digits == 0 {
		digits = defaultTOTPDigits
	}
	if digits != 6 && digits != 8 {
		return nil, errors.New("MFA.TOTP.Digits must be 6 or 8")
	}
	period := o.Period
	if period == 0 {
		period = defaultTOTPPeriod
	}
	if period < 15 || period > 120 {
		return nil, errors.New("MFA.TOTP.Period must be between 15 and 120")
	}
	skew := o.Skew
	if skew == 0 {
		skew = defaultTOTPSkew
	}
	encKey, err := hkdf.Key(sha256.New, []byte(jwtSecret), nil, "goauth totp enc v1", 32)
	if err != nil {
		return nil, err
	}
	hashKey, err := hkdf.Key(sha256.New, []byte(jwtSecret), nil, "goauth totp hash v1", 32)
	if err != nil {
		return nil, err
	}
	return &totpMFA{
		enabled: true,
		issuer:  cmp.Or(o.Issuer, appName, defaultTOTPIssuer),
		table:   cmp.Or(o.TableName, defaultTOTPTable),
		digits:  digits,
		period:  period,
		skew:    skew,
		encKey:  encKey,
		hashKey: hashKey,
		limiter: newMFALimiter(),
	}, nil
}

func (a *Authorization) totpEnabled() bool {
	return a != nil && a.totp != nil && a.totp.enabled
}
