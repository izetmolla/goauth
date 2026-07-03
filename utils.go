package goauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// httpClient is overridable in tests; defaults to a sane client.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// IsExcludedPath reports whether `path` starts with any prefix in
// `excluded`. Prefix matching is intentional so callers can opt entire
// route trees out of authentication (e.g. "/api/public").
func IsExcludedPath(excluded []string, path string) bool {
	for _, prefix := range excluded {
		if prefix == "" {
			continue
		}
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// validateSessionData validates session data for required fields.
func validateSessionData(session *SessionData) error {
	if session == nil {
		return fmt.Errorf("session data cannot be nil")
	}
	if session.ID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}
	if session.UserID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	return nil
}

// buildRedisKey creates a Redis key with the configured prefix.
func buildRedisKey(prefix, sessionID string) string {
	if prefix == "" {
		prefix = "ft_auth"
	}
	return fmt.Sprintf("%s:%s", prefix, sessionID)
}

// serializeSessionData serializes session data to JSON for Redis storage.
func serializeSessionData(session *SessionData) ([]byte, error) {
	if session == nil {
		return nil, fmt.Errorf("session data cannot be nil")
	}

	data, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session data: %w", err)
	}

	return data, nil
}

// deserializeSessionData deserializes JSON data from Redis into session data.
func deserializeSessionData(data []byte) (*SessionData, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("session data is empty")
	}

	var response SessionData
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}
	if err := validateSessionData(&response); err != nil {
		return nil, err
	}

	return &response, nil
}

func resolveSigningMethod(method string) *jwt.SigningMethodHMAC {
	switch strings.ToLower(method) {
	case "hs384":
		return jwt.SigningMethodHS384
	case "hs512":
		return jwt.SigningMethodHS512
	case "hs256", "":
		return jwt.SigningMethodHS256
	default:
		return jwt.SigningMethodHS256
	}
}

// --- Duration parsing -----------------------------------------------------

// unitMultipliers maps the package's custom duration units to their value.
//
// Declared as a package-level variable so it is allocated once instead of
// on every ParseCustomDuration call.
var unitMultipliers = map[string]time.Duration{
	"s":  time.Second,
	"m":  time.Minute,
	"h":  time.Hour,
	"d":  24 * time.Hour,
	"w":  7 * 24 * time.Hour,
	"mo": 30 * 24 * time.Hour,  // approximate month
	"y":  365 * 24 * time.Hour, // approximate year
}

// ParseCustomDuration parses values such as "30s", "15m", "1h", "7d",
// "4w", "1mo" or "1y". The empty string falls back to `defaultInput`.
//
// Kept as a package-level function (and the historical method on
// TokenManager forwards to it) so callers can reach it without a
// TokenManager instance.
func ParseCustomDuration(input, defaultInput string) (time.Duration, error) {
	if input == "" {
		input = defaultInput
	}

	// Split into the numeric prefix and the unit suffix without
	// allocating two strings.Builders like the previous implementation.
	splitAt := len(input)
	for i, r := range input {
		if r < '0' || r > '9' {
			splitAt = i
			break
		}
	}
	if splitAt == 0 {
		return 0, errors.New("invalid duration: missing number")
	}

	num, err := strconv.Atoi(input[:splitAt])
	if err != nil {
		return 0, fmt.Errorf("invalid number: %w", err)
	}
	unit := input[splitAt:]
	multiplier, ok := unitMultipliers[unit]
	if !ok {
		return 0, fmt.Errorf("invalid time unit: %q", unit)
	}
	return time.Duration(num) * multiplier, nil
}

// stringClaim safely extracts a string value from jwt.MapClaims.
func stringClaim(claims jwt.MapClaims, key string) string {
	if v, ok := claims[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func FormatUser(user *User) any {
	if user == nil {
		return map[string]any{}
	}
	formattedUser := map[string]any{
		"id":    user.ID,
		"roles": user.Roles,
	}

	if user.User != nil {
		maps.Copy(formattedUser, user.User)
	}
	return formattedUser
}
