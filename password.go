package goauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	passwordSaltBytes    = 16
	passwordKeyBytes     = 32
	passwordIterations   = 600_000
	passwordHashPrefix   = "$pbkdf2-sha256$"
	passwordHashSegments = 3
)

// HashPassword returns a PBKDF2-SHA256 hash of password suitable for database
// storage. The encoded form is self-describing:
//
//	$pbkdf2-sha256$<iterations>$<salt>$<hash>
//
// Salt and hash segments use base64 raw URL encoding (no padding).
func HashPassword(password string) (string, error) {
	salt := make([]byte, passwordSaltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	return encodePasswordHash(passwordIterations, salt, password), nil
}

// CheckPassword reports whether password matches a hash produced by HashPassword.
func CheckPassword(hash, password string) bool {
	iter, salt, want, err := decodePasswordHash(hash)
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func encodePasswordHash(iterations int, salt []byte, password string) string {
	key := pbkdf2SHA256([]byte(password), salt, iterations, passwordKeyBytes)
	enc := base64.RawURLEncoding
	return fmt.Sprintf("%s%d$%s$%s",
		passwordHashPrefix,
		iterations,
		enc.EncodeToString(salt),
		enc.EncodeToString(key),
	)
}

func decodePasswordHash(hash string) (iterations int, salt, key []byte, err error) {
	if !strings.HasPrefix(hash, passwordHashPrefix) {
		return 0, nil, nil, errors.New("goauth: unknown password hash format")
	}
	parts := strings.Split(hash[len(passwordHashPrefix):], "$")
	if len(parts) != passwordHashSegments {
		return 0, nil, nil, errors.New("goauth: malformed password hash")
	}
	iterations, err = strconv.Atoi(parts[0])
	if err != nil || iterations <= 0 {
		return 0, nil, nil, errors.New("goauth: invalid password hash iterations")
	}
	enc := base64.RawURLEncoding
	salt, err = enc.DecodeString(parts[1])
	if err != nil {
		return 0, nil, nil, errors.New("goauth: invalid password hash salt")
	}
	key, err = enc.DecodeString(parts[2])
	if err != nil {
		return 0, nil, nil, errors.New("goauth: invalid password hash digest")
	}
	return iterations, salt, key, nil
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := func(key, msg []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(msg)
		return mac.Sum(nil)
	}
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	for block := 1; block <= numBlocks; block++ {
		msg := make([]byte, len(salt)+4)
		copy(msg, salt)
		msg[len(salt)] = byte(block >> 24)
		msg[len(salt)+1] = byte(block >> 16)
		msg[len(salt)+2] = byte(block >> 8)
		msg[len(salt)+3] = byte(block)
		u := prf(password, msg)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			u = prf(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
