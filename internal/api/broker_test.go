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

func TestBroker_MaxWaitUnderContinuousNotify(t *testing.T) {
	b := NewBroker(50 * time.Millisecond)
	defer b.Shutdown()

	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-ch:
			return
		case <-deadline:
			t.Fatal("no broadcast under continuous notifications — debounce starvation")
		case <-ticker.C:
			b.Notify()
		}
	}
}

func TestBroker_ShutdownClosesSubscribers(t *testing.T) {
	b := NewBroker(10 * time.Millisecond)
	ch := b.Subscribe()

	b.Shutdown()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected closed channel, got value")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("subscriber channel not closed on shutdown")
	}

	b.Unsubscribe(ch) // must not panic on already-closed channel
	b.Shutdown()      // idempotent
}

func TestBroker_ShutdownCancelsPendingBroadcast(t *testing.T) {
	b := NewBroker(50 * time.Millisecond)
	ch := b.Subscribe()

	b.Notify()
	b.Shutdown()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected closed channel, got broadcast after shutdown")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("subscriber channel not closed")
	}
}

func TestBroker_SubscribeAfterShutdownReturnsClosedChannel(t *testing.T) {
	b := NewBroker(10 * time.Millisecond)
	b.Shutdown()

	ch := b.Subscribe()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected closed channel, got value")
		}
	default:
		t.Fatal("channel from post-shutdown Subscribe should already be closed")
	}
}

func TestBroker_SubscriberCount(t *testing.T) {
	b := NewBroker(10 * time.Millisecond)
	defer b.Shutdown()

	if got := b.SubscriberCount(); got != 0 {
		t.Fatalf("count = %d, want 0", got)
	}
	ch := b.Subscribe()
	if got := b.SubscriberCount(); got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}
	b.Unsubscribe(ch)
	if got := b.SubscriberCount(); got != 0 {
		t.Fatalf("count = %d, want 0 after unsubscribe", got)
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
