// Copyright © 2026 Marcel Joachim Kloubert <marcel@kloubert.dev>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

package security

import (
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type ipEntry struct {
	limiter   *rate.Limiter
	failures  atomic.Int32
	blockedAt atomic.Int64 // unix nano, 0 = not blocked
}

// RateLimiter provides per-IP rate limiting and failed-handshake tracking.
// IPs that exceed the failure threshold are blocked for a configurable duration.
type RateLimiter struct {
	entries       sync.Map
	ratePerSec    rate.Limit
	burst         int
	maxFailures   int32
	blockDuration time.Duration
	done          chan struct{}
}

// NewRateLimiter creates a RateLimiter. ratePerSec is the sustained rate,
// burst is the maximum burst size, maxFailures is the number of failed
// handshakes before blocking, and blockDuration is how long to block.
func NewRateLimiter(ratePerSec float64, burst int, maxFailures int, blockDuration time.Duration) *RateLimiter {
	rl := &RateLimiter{
		ratePerSec:    rate.Limit(ratePerSec),
		burst:         burst,
		maxFailures:   int32(maxFailures),
		blockDuration: blockDuration,
		done:          make(chan struct{}),
	}

	go rl.cleanup()

	return rl
}

// Allow checks if a connection from the given IP should be permitted.
// Returns false if the IP is blocked or rate-limited.
func (rl *RateLimiter) Allow(ip string) bool {
	entry := rl.getOrCreate(ip)

	// Check if IP is blocked due to failed handshakes
	if blockedAt := entry.blockedAt.Load(); blockedAt > 0 {
		if time.Now().UnixNano()-blockedAt < int64(rl.blockDuration) {
			return false
		}
		// Block expired: reset
		entry.blockedAt.Store(0)
		entry.failures.Store(0)
	}

	return entry.limiter.Allow()
}

// RecordFailure increments the failure counter for an IP. When the counter
// reaches the threshold, the IP is blocked for blockDuration.
func (rl *RateLimiter) RecordFailure(ip string) {
	entry := rl.getOrCreate(ip)
	if entry.failures.Add(1) >= rl.maxFailures {
		entry.blockedAt.Store(time.Now().UnixNano())
	}
}

// Stop terminates the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	select {
	case <-rl.done:
	default:
		close(rl.done)
	}
}

func (rl *RateLimiter) getOrCreate(ip string) *ipEntry {
	if v, ok := rl.entries.Load(ip); ok {
		return v.(*ipEntry)
	}
	entry := &ipEntry{
		limiter: rate.NewLimiter(rl.ratePerSec, rl.burst),
	}
	actual, _ := rl.entries.LoadOrStore(ip, entry)
	return actual.(*ipEntry)
}

// cleanup removes stale entries every 60 seconds.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rl.done:
			return
		case <-ticker.C:
			now := time.Now().UnixNano()
			rl.entries.Range(func(key, value any) bool {
				entry := value.(*ipEntry)
				blockedAt := entry.blockedAt.Load()
				if blockedAt == 0 && entry.failures.Load() == 0 {
					rl.entries.Delete(key)
				}
				if blockedAt > 0 && now-blockedAt > int64(2*rl.blockDuration) {
					rl.entries.Delete(key)
				}
				return true
			})
		}
	}
}
