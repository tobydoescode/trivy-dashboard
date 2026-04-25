package api

import (
	"sync"
	"time"
)

// Broker fans out store-change notifications to connected SSE clients.
// Notifications are debounced — rapid changes coalesce into one event
// after the debounce interval elapses with no new changes.
type Broker struct {
	mu          sync.Mutex
	subscribers map[chan struct{}]struct{}
	debounce    time.Duration
	timer       *time.Timer
	done        chan struct{}
}

// NewBroker creates a broker with the given debounce interval.
func NewBroker(debounce time.Duration) *Broker {
	return &Broker{
		subscribers: make(map[chan struct{}]struct{}),
		debounce:    debounce,
		done:        make(chan struct{}),
	}
}

// Subscribe returns a channel that receives a value each time the
// dashboard should refresh.
func (b *Broker) Subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (b *Broker) Unsubscribe(ch chan struct{}) {
	b.mu.Lock()
	delete(b.subscribers, ch)
	b.mu.Unlock()
	close(ch)
}

// Notify signals that the store changed. The actual broadcast is
// debounced — if Notify is called again within the debounce window,
// the timer resets.
func (b *Broker) Notify() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.timer != nil {
		b.timer.Stop()
	}
	b.timer = time.AfterFunc(b.debounce, b.broadcast)
}

func (b *Broker) broadcast() {
	b.mu.Lock()
	defer b.mu.Unlock()

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

// Shutdown stops the broker and prevents further broadcasts.
func (b *Broker) Shutdown() {
	b.mu.Lock()
	defer b.mu.Unlock()
	close(b.done)
	if b.timer != nil {
		b.timer.Stop()
	}
}
