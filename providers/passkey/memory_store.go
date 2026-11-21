package passkey

import (
	"bytes"
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-memory Store for tests and local demos. Do not use in
// production (challenges and credentials are lost on restart).
type MemoryStore struct {
	mu          sync.Mutex
	users       map[string]*User          // by user id
	byHandle    map[string]string         // handle hex -> user id
	credentials map[string][]Credential   // by user id
	challenges  map[string]challengeEntry // by challenge key
}

type challengeEntry struct {
	data []byte
	exp  time.Time
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:       map[string]*User{},
		byHandle:    map[string]string{},
		credentials: map[string][]Credential{},
		challenges:  map[string]challengeEntry{},
	}
}

// SeedUser registers a user record so registration/login can resolve them.
func (s *MemoryStore) SeedUser(u User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := u
	s.users[u.ID] = &cp
	if len(u.Handle) > 0 {
		s.byHandle[string(u.Handle)] = u.ID
	}
}

func (s *MemoryStore) GetUser(_ context.Context, userID string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[userID]
	if u == nil {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

func (s *MemoryStore) GetUserByHandle(_ context.Context, handle []byte) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.byHandle[string(handle)]
	if id == "" {
		return nil, nil
	}
	u := s.users[id]
	if u == nil {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

func (s *MemoryStore) EnsureUserHandle(_ context.Context, userID string, handle []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[userID]
	if u == nil {
		u = &User{ID: userID, Name: userID, DisplayName: userID}
		s.users[userID] = u
	}
	if len(u.Handle) == 0 {
		u.Handle = append([]byte(nil), handle...)
		s.byHandle[string(handle)] = userID
	}
	return nil
}

func (s *MemoryStore) ListCredentials(_ context.Context, userID string) ([]Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Credential(nil), s.credentials[userID]...)
	return out, nil
}

func (s *MemoryStore) SaveCredential(_ context.Context, userID string, cred Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[userID] = append(s.credentials[userID], cred)
	return nil
}

func (s *MemoryStore) UpdateCredential(_ context.Context, userID string, cred Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.credentials[userID]
	for i := range list {
		if bytes.Equal(list[i].ID, cred.ID) {
			list[i] = cred
			s.credentials[userID] = list
			return nil
		}
	}
	s.credentials[userID] = append(list, cred)
	return nil
}

func (s *MemoryStore) PutChallenge(_ context.Context, id string, data []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[id] = challengeEntry{data: append([]byte(nil), data...), exp: time.Now().Add(ttl)}
	return nil
}

func (s *MemoryStore) TakeChallenge(_ context.Context, id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.challenges[id]
	if !ok {
		return nil, nil
	}
	delete(s.challenges, id)
	if time.Now().After(e.exp) {
		return nil, nil
	}
	return append([]byte(nil), e.data...), nil
}
