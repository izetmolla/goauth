package goauth

import (
	"sync"
	"time"
)

const (
	// mfaMaxFailures is how many wrong authenticator or backup codes a user
	// may submit inside mfaFailureWindow before further attempts are refused.
	// A 6-digit code with skew 1 has 3 valid values in a million, so without
	// a cap a stolen password plus a scripted loop gets through quickly.
	mfaMaxFailures   = 5
	mfaFailureWindow = mfaChallengeTTL

	codeMFATooMany = "MFA_TOO_MANY_ATTEMPTS"
	msgMFATooMany  = "Too many incorrect codes. Wait a few minutes and try again."
)

// mfaLimiter counts failed MFA codes per user. It is in-memory, so with
// several app instances each enforces its own cap; that still bounds an
// attacker to a small multiple of mfaMaxFailures per window.
type mfaLimiter struct {
	mu    sync.Mutex
	now   func() time.Time
	users map[string]*mfaFailures
}

type mfaFailures struct {
	count int
	reset time.Time
}

func newMFALimiter() *mfaLimiter {
	return &mfaLimiter{now: time.Now, users: map[string]*mfaFailures{}}
}

// blocked reports whether the user has used up their attempts.
func (l *mfaLimiter) blocked(userID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.users[userID]
	if !ok {
		return false
	}
	if !l.now().Before(f.reset) {
		delete(l.users, userID)
		return false
	}
	return f.count >= mfaMaxFailures
}

// fail records one wrong code.
func (l *mfaLimiter) fail(userID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	f, ok := l.users[userID]
	if !ok || !now.Before(f.reset) {
		f = &mfaFailures{reset: now.Add(mfaFailureWindow)}
		l.users[userID] = f
	}
	f.count++
	// Drop expired entries now and then so the map can't grow without bound.
	if len(l.users) > 1024 {
		for id, v := range l.users {
			if !now.Before(v.reset) {
				delete(l.users, id)
			}
		}
	}
}

// succeed clears the user's failures after a correct code.
func (l *mfaLimiter) succeed(userID string) {
	l.mu.Lock()
	delete(l.users, userID)
	l.mu.Unlock()
}
