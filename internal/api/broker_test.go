package api

import (
	"testing"
	"time"
)

func TestBroker_SubscribeReceivesNotification(t *testing.T) {
	b := NewBroker(50 * time.Millisecond)
	defer b.Shutdown()

	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	b.Notify()

	select {
	case <-ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for notification")
	}
}

func TestBroker_Debounce(t *testing.T) {
	b := NewBroker(100 * time.Millisecond)
	defer b.Shutdown()

	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	for i := 0; i < 10; i++ {
		b.Notify()
	}

	select {
	case <-ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for debounced notification")
	}

	select {
	case <-ch:
		t.Fatal("received extra notification — debounce failed")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBroker_UnsubscribeRemovesFromSet(t *testing.T) {
	b := NewBroker(10 * time.Millisecond)
	defer b.Shutdown()

	ch1 := b.Subscribe()
	ch2 := b.Subscribe()
	b.Unsubscribe(ch1)

	b.Notify()

	select {
	case <-ch2:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("remaining subscriber should still receive")
	}

	b.mu.Lock()
	count := len(b.subscribers)
	b.mu.Unlock()
	if count != 1 {
		t.Errorf("subscriber count = %d, want 1", count)
	}
}

func TestBroker_MultipleSubscribers(t *testing.T) {
	b := NewBroker(10 * time.Millisecond)
	defer b.Shutdown()

	ch1 := b.Subscribe()
	ch2 := b.Subscribe()
	defer b.Unsubscribe(ch1)
	defer b.Unsubscribe(ch2)

	b.Notify()

	for i, ch := range []<-chan struct{}{ch1, ch2} {
		select {
		case <-ch:
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("subscriber %d timed out", i)
		}
	}
}
