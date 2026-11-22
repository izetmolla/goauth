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
	// used holds each user's last accepted TOTP time step, so a code cannot
	// be used twice. Like the failure counts it is per instance.
	used map[string]usedStep
}

// usedStep is the last accepted TOTP step and when it can be forgotten.
type usedStep struct {
	step    int64
	expires time.Time
}

type mfaFailures struct {
	count int
	reset time.Time
}

func newMFALimiter() *mfaLimiter {
	return &mfaLimiter{now: time.Now, users: map[string]*mfaFailures{}, used: map[string]usedStep{}}
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

// useStep records an accepted TOTP step and reports whether it is new: a
// step at or before the user's last accepted one is a replay. Entries are
// kept for mfaFailureWindow, longer than any code stays valid.
func (l *mfaLimiter) useStep(userID string, step int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if last, ok := l.used[userID]; ok && now.Before(last.expires) && step <= last.step {
		return false
	}
	l.used[userID] = usedStep{step: step, expires: now.Add(mfaFailureWindow)}
	if len(l.used) > 1024 {
		for id, v := range l.used {
			if !now.Before(v.expires) {
				delete(l.used, id)
			}
		}
	}
	return true
}
