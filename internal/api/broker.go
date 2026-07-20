package api

import (
	"sync"
	"time"
)

// Broker fans out store-change notifications to connected SSE clients.
// Notifications are debounced — rapid changes coalesce into one event
// after the debounce interval elapses with no new changes, capped so a
// continuous stream of changes cannot starve broadcasts forever.
type Broker struct {
	mu          sync.Mutex
	subscribers map[chan struct{}]struct{}
	debounce    time.Duration
	maxWait     time.Duration
	timer       *time.Timer
	pending     time.Time
	done        chan struct{}
}

// NewBroker creates a broker with the given debounce interval. A broadcast
// is guaranteed within roughly 4x the debounce interval of the first
// pending notification, even under continuous change.
func NewBroker(debounce time.Duration) *Broker {
	return &Broker{
		subscribers: make(map[chan struct{}]struct{}),
		debounce:    debounce,
		maxWait:     4 * debounce,
		done:        make(chan struct{}),
	}
}

// Subscribe returns a channel that receives a value each time the
// dashboard should refresh. After Shutdown the returned channel is
// already closed.
func (b *Broker) Subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.done:
		close(ch)
		return ch
	default:
	}
	b.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes a subscriber and closes its channel. Safe to call
// after Shutdown has already closed the channel.
func (b *Broker) Unsubscribe(ch chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

// SubscriberCount returns the number of connected subscribers.
func (b *Broker) SubscriberCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subscribers)
}

// Notify signals that the store changed. The actual broadcast is
// debounced — if Notify is called again within the debounce window, the
// timer resets, but once the oldest pending notification is maxWait old
// the scheduled broadcast is left to fire.
func (b *Broker) Notify() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	if b.timer == nil {
		b.pending = now
	} else {
		if now.Sub(b.pending) >= b.maxWait {
			return
		}
		b.timer.Stop()
	}
	b.timer = time.AfterFunc(b.debounce, b.broadcast)
}

func (b *Broker) broadcast() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.timer = nil

	select {
	case <-b.done:
		return
	default:
	}

	for ch := range b.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Shutdown stops the broker, prevents further broadcasts, and closes all
// subscriber channels so blocked SSE handlers unwind. Idempotent.
func (b *Broker) Shutdown() {
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.done:
		return
	default:
	}
	close(b.done)
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	for ch := range b.subscribers {
		close(ch)
	}
	b.subscribers = make(map[chan struct{}]struct{})
}
