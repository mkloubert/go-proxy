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
	"testing"
	"time"
)

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(10, 5, 5, 1*time.Minute)
	defer rl.Stop()

	for i := 0; i < 5; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i)
		}
	}

	// Burst exhausted
	if rl.Allow("1.2.3.4") {
		t.Fatal("request after burst should be rejected")
	}

	// Different IP should still be allowed
	if !rl.Allow("5.6.7.8") {
		t.Fatal("different IP should be allowed")
	}
}

func TestRateLimiterFailureBlocking(t *testing.T) {
	rl := NewRateLimiter(100, 100, 3, 1*time.Minute)
	defer rl.Stop()

	ip := "9.8.7.6"

	rl.RecordFailure(ip)
	rl.RecordFailure(ip)

	if !rl.Allow(ip) {
		t.Fatal("should be allowed before reaching failure threshold")
	}

	// Third failure triggers block
	rl.RecordFailure(ip)

	if rl.Allow(ip) {
		t.Fatal("should be blocked after reaching failure threshold")
	}

	// Other IPs unaffected
	if !rl.Allow("1.1.1.1") {
		t.Fatal("other IP should not be affected")
	}
}

func TestRateLimiterFailureExpiry(t *testing.T) {
	rl := NewRateLimiter(100, 100, 2, 50*time.Millisecond)
	defer rl.Stop()

	ip := "11.22.33.44"

	rl.RecordFailure(ip)
	rl.RecordFailure(ip)

	if rl.Allow(ip) {
		t.Fatal("should be blocked")
	}

	time.Sleep(100 * time.Millisecond)

	if !rl.Allow(ip) {
		t.Fatal("should be allowed after block expires")
	}
}

func TestRateLimiterExponentialBackoff(t *testing.T) {
	// Use very short block durations so the test runs fast
	rl := NewRateLimiter(100, 100, 2, 50*time.Millisecond)
	defer rl.Stop()

	ip := "55.66.77.88"

	// First block (50ms)
	rl.RecordFailure(ip)
	rl.RecordFailure(ip)

	if rl.Allow(ip) {
		t.Fatal("should be blocked after first set of failures")
	}

	// Wait for first block to expire (50ms)
	time.Sleep(80 * time.Millisecond)

	if !rl.Allow(ip) {
		t.Fatal("should be allowed after first block expires")
	}

	// Second block should be longer (100ms = 50ms * 2^1)
	rl.RecordFailure(ip)
	rl.RecordFailure(ip)

	if rl.Allow(ip) {
		t.Fatal("should be blocked after second set of failures")
	}

	// First block duration (50ms) should NOT be enough
	time.Sleep(70 * time.Millisecond)

	if rl.Allow(ip) {
		t.Fatal("should still be blocked during exponential backoff")
	}

	// Wait for the rest of the second block to expire
	time.Sleep(80 * time.Millisecond)

	if !rl.Allow(ip) {
		t.Fatal("should be allowed after second block expires")
	}
}

func TestRateLimiterStop(t *testing.T) {
	rl := NewRateLimiter(10, 5, 5, 1*time.Minute)
	rl.Stop()

	// Should not panic after stop
	if !rl.Allow("1.2.3.4") {
		t.Fatal("Allow after Stop should still work")
	}
}
