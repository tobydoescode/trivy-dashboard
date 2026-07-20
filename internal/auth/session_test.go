package auth

import (
	"testing"
	"time"
)

func TestSessionStore_CreateAndValid(t *testing.T) {
	s := NewSessionStore(time.Hour)
	id := s.Create()
	if id == "" {
		t.Fatal("Create returned empty ID")
	}
	if !s.Valid(id) {
		t.Error("freshly created session should be valid")
	}
	if s.Valid("not-a-session") {
		t.Error("unknown ID should be invalid")
	}
}

func TestSessionStore_IDsAreUnique(t *testing.T) {
	s := NewSessionStore(time.Hour)
	if s.Create() == s.Create() {
		t.Error("two sessions got the same ID")
	}
}

func TestSessionStore_TTL(t *testing.T) {
	s := NewSessionStore(time.Hour)
	if s.TTL() != time.Hour {
		t.Errorf("TTL = %v, want 1h", s.TTL())
	}
}

func TestSessionStore_Expiry(t *testing.T) {
	s := NewSessionStore(time.Millisecond)
	id := s.Create()
	time.Sleep(5 * time.Millisecond)
	if s.Valid(id) {
		t.Error("expired session should be invalid")
	}
}

func TestSessionStore_Delete(t *testing.T) {
	s := NewSessionStore(time.Hour)
	id := s.Create()
	s.Delete(id)
	if s.Valid(id) {
		t.Error("deleted session should be invalid")
	}
}

func TestSessionStore_CreatePrunesExpired(t *testing.T) {
	s := NewSessionStore(time.Millisecond)
	s.Create()
	time.Sleep(5 * time.Millisecond)
	s.Create()

	s.mu.Lock()
	n := len(s.sessions)
	s.mu.Unlock()
	if n != 1 {
		t.Errorf("sessions = %d, want 1 after pruning", n)
	}
}
