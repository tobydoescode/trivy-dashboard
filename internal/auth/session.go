package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// SessionStore mints and validates random browser session IDs so the real
// bearer token never has to live in a cookie or browser storage.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	ttl      time.Duration
}

// NewSessionStore creates a SessionStore whose sessions expire after ttl.
func NewSessionStore(ttl time.Duration) *SessionStore {
	return &SessionStore{sessions: make(map[string]time.Time), ttl: ttl}
}

// Create mints a new random session ID and records its expiry. Expired
// sessions are pruned as a side effect.
func (s *SessionStore) Create() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("auth: crypto/rand failed: " + err.Error())
	}
	id := base64.RawURLEncoding.EncodeToString(buf)

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = now.Add(s.ttl)
	return id
}

// Valid reports whether id is a live session. Expired sessions are removed.
func (s *SessionStore) Valid(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[id]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, id)
		return false
	}
	return true
}

// Delete removes a session, if present.
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// TTL returns the session lifetime.
func (s *SessionStore) TTL() time.Duration {
	return s.ttl
}
