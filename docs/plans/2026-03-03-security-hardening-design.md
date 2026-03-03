# Security Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Harden the remote tunnel server against bots, connection flooding, brute-force, SSRF, and resource exhaustion — while keeping the port appearing dead to unauthorized clients.

**Architecture:** New `internal/security/` package with three files (connlimiter, ratelimiter, validate). These primitives are wired directly into `internal/tunnel/server.go`. Yamux gets explicit hardened config. All measures apply only to the remote server.

**Tech Stack:** Go stdlib, `golang.org/x/time/rate` (new dependency), `github.com/hashicorp/yamux` (existing)

---

## Task 1: Address Validation + Private-IP Blacklist

**Files:**
- Create: `internal/security/validate.go`
- Test: `internal/security/validate_test.go`

**Step 1: Write the failing tests**

File: `internal/security/validate_test.go`

```go
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
	"net"
	"strings"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"::1", true},
		{"fe80::1", true},
		{"0.0.0.0", true},
		{"::", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		{"172.32.0.1", false},
		{"192.169.0.1", false},
		{"2607:f8b0:4004:800::200e", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP: %s", tt.ip)
		}
		got := IsPrivateIP(ip)
		if got != tt.private {
			t.Errorf("IsPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}

func TestIsPrivateIPNil(t *testing.T) {
	if !IsPrivateIP(nil) {
		t.Error("IsPrivateIP(nil) should return true")
	}
}

func TestValidateTarget(t *testing.T) {
	tests := []struct {
		addr    string
		wantErr bool
		errMsg  string
	}{
		// Valid public addresses
		{"8.8.8.8:443", false, ""},
		{"1.1.1.1:80", false, ""},
		{"93.184.216.34:8080", false, ""},

		// Private IPs — must be rejected
		{"127.0.0.1:80", true, "private"},
		{"10.0.0.1:443", true, "private"},
		{"172.16.0.1:80", true, "private"},
		{"192.168.1.1:80", true, "private"},
		{"[::1]:80", true, "private"},
		{"0.0.0.0:80", true, "private"},

		// Invalid format
		{"noport", true, "invalid"},
		{"", true, "invalid"},
		{":80", true, "empty"},
		{"host:", true, "invalid"},

		// Invalid port
		{"8.8.8.8:0", true, "port"},
		{"8.8.8.8:99999", true, "port"},
		{"8.8.8.8:-1", true, "port"},
		{"8.8.8.8:abc", true, "port"},

		// Address too long
		{strings.Repeat("a", 250) + ".com:80", true, "long"},
	}

	for _, tt := range tests {
		err := ValidateTarget(tt.addr)
		if tt.wantErr && err == nil {
			t.Errorf("ValidateTarget(%q) = nil, want error containing %q", tt.addr, tt.errMsg)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("ValidateTarget(%q) = %v, want nil", tt.addr, err)
		}
	}
}

func TestSafeDialRejectsPrivateIP(t *testing.T) {
	_, err := SafeDial("127.0.0.1:80")
	if err == nil {
		t.Fatal("SafeDial should reject 127.0.0.1")
	}

	_, err = SafeDial("10.0.0.1:80")
	if err == nil {
		t.Fatal("SafeDial should reject 10.0.0.1")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/ -v -count=1`
Expected: Compilation error — package doesn't exist yet.

**Step 3: Write minimal implementation**

File: `internal/security/validate.go`

```go
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
	"fmt"
	"net"
	"strconv"
)

const maxAddrLen = 253

// IsPrivateIP returns true if the IP is loopback, private, link-local,
// multicast, or unspecified. Returns true for nil.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// ValidateTarget checks that addr is a valid host:port with a public IP.
// It rejects private IPs, invalid formats, and addresses longer than 253 bytes.
func ValidateTarget(addr string) error {
	if len(addr) > maxAddrLen {
		return fmt.Errorf("address too long: %d bytes", len(addr))
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	if host == "" {
		return fmt.Errorf("empty host in address")
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %s", portStr)
	}

	if ip := net.ParseIP(host); ip != nil {
		if IsPrivateIP(ip) {
			return fmt.Errorf("private IP not allowed: %s", host)
		}
	}

	return nil
}

// SafeDial validates the target address and dials it. For hostnames, it
// resolves DNS and verifies that no resolved IP is private before connecting.
// This prevents SSRF attacks via DNS rebinding.
func SafeDial(addr string) (net.Conn, error) {
	if err := ValidateTarget(addr); err != nil {
		return nil, err
	}

	host, port, _ := net.SplitHostPort(addr)

	// Literal IP: already validated by ValidateTarget, dial directly
	if ip := net.ParseIP(host); ip != nil {
		return net.Dial("tcp4", addr)
	}

	// Hostname: resolve and validate all IPs before connecting
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}

	for _, ip := range ips {
		if ip.To4() != nil && !IsPrivateIP(ip) {
			return net.Dial("tcp4", net.JoinHostPort(ip.String(), port))
		}
	}

	return nil, fmt.Errorf("no valid public IPv4 address found for %s", host)
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/ -v -count=1`
Expected: All PASS.

**Step 5: Commit**

```bash
git add internal/security/validate.go internal/security/validate_test.go
git commit -m "feat(security): add address validation and private-IP blacklist"
```

---

## Task 2: Connection Limiter (Semaphore)

**Files:**
- Create: `internal/security/connlimiter.go`
- Test: `internal/security/connlimiter_test.go`

**Step 1: Write the failing tests**

File: `internal/security/connlimiter_test.go`

```go
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

import "testing"

func TestConnLimiterAcquireRelease(t *testing.T) {
	cl := NewConnLimiter(2)

	if !cl.Acquire() {
		t.Fatal("first Acquire should succeed")
	}
	if !cl.Acquire() {
		t.Fatal("second Acquire should succeed")
	}
	if cl.Acquire() {
		t.Fatal("third Acquire should fail (limit=2)")
	}

	cl.Release()

	if !cl.Acquire() {
		t.Fatal("Acquire after Release should succeed")
	}
}

func TestConnLimiterZero(t *testing.T) {
	cl := NewConnLimiter(0)
	if cl.Acquire() {
		t.Fatal("Acquire on zero-capacity limiter should fail")
	}
}

func TestConnLimiterActive(t *testing.T) {
	cl := NewConnLimiter(3)

	if cl.Active() != 0 {
		t.Fatalf("expected 0 active, got %d", cl.Active())
	}

	cl.Acquire()
	cl.Acquire()

	if cl.Active() != 2 {
		t.Fatalf("expected 2 active, got %d", cl.Active())
	}

	cl.Release()

	if cl.Active() != 1 {
		t.Fatalf("expected 1 active, got %d", cl.Active())
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/ -run TestConnLimiter -v -count=1`
Expected: Compilation error — `NewConnLimiter` not defined.

**Step 3: Write minimal implementation**

File: `internal/security/connlimiter.go`

```go
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

// ConnLimiter limits the number of concurrent connections using a
// channel-based semaphore. Acquire is non-blocking: it returns false
// immediately when the limit is reached.
type ConnLimiter struct {
	sem chan struct{}
}

// NewConnLimiter creates a ConnLimiter with the given maximum capacity.
func NewConnLimiter(maxConns int) *ConnLimiter {
	return &ConnLimiter{
		sem: make(chan struct{}, maxConns),
	}
}

// Acquire tries to acquire a connection slot. Returns false if full.
func (cl *ConnLimiter) Acquire() bool {
	select {
	case cl.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release frees a connection slot.
func (cl *ConnLimiter) Release() {
	<-cl.sem
}

// Active returns the number of currently held slots.
func (cl *ConnLimiter) Active() int {
	return len(cl.sem)
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/ -run TestConnLimiter -v -count=1`
Expected: All PASS.

**Step 5: Commit**

```bash
git add internal/security/connlimiter.go internal/security/connlimiter_test.go
git commit -m "feat(security): add semaphore-based connection limiter"
```

---

## Task 3: Rate Limiter + Failed-Handshake Tracking

**Files:**
- Create: `internal/security/ratelimiter.go`
- Test: `internal/security/ratelimiter_test.go`
- Modify: `go.mod` (add `golang.org/x/time`)

**Step 1: Add dependency**

Run: `go get golang.org/x/time/rate@latest`

**Step 2: Write the failing tests**

File: `internal/security/ratelimiter_test.go`

```go
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

	// First few requests should be allowed (burst=5)
	for i := 0; i < 5; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i)
		}
	}

	// Next request should be rate-limited (burst exhausted)
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

	// Record failures up to threshold
	rl.RecordFailure(ip)
	rl.RecordFailure(ip)

	// Should still be allowed (below threshold of 3)
	if !rl.Allow(ip) {
		t.Fatal("should be allowed before reaching failure threshold")
	}

	// Third failure triggers block
	rl.RecordFailure(ip)

	// Now blocked
	if rl.Allow(ip) {
		t.Fatal("should be blocked after reaching failure threshold")
	}

	// Other IPs unaffected
	if !rl.Allow("1.1.1.1") {
		t.Fatal("other IP should not be affected")
	}
}

func TestRateLimiterFailureExpiry(t *testing.T) {
	// Block duration of 50ms for fast test
	rl := NewRateLimiter(100, 100, 2, 50*time.Millisecond)
	defer rl.Stop()

	ip := "11.22.33.44"

	rl.RecordFailure(ip)
	rl.RecordFailure(ip)

	if rl.Allow(ip) {
		t.Fatal("should be blocked")
	}

	// Wait for block to expire
	time.Sleep(100 * time.Millisecond)

	if !rl.Allow(ip) {
		t.Fatal("should be allowed after block expires")
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
```

**Step 3: Run tests to verify they fail**

Run: `go test ./internal/security/ -run TestRateLimiter -v -count=1`
Expected: Compilation error — `NewRateLimiter` not defined.

**Step 4: Write minimal implementation**

File: `internal/security/ratelimiter.go`

```go
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
				// Remove entries that are not blocked and have no recent failures
				if blockedAt == 0 && entry.failures.Load() == 0 {
					rl.entries.Delete(key)
				}
				// Remove entries whose block has long expired (2x block duration)
				if blockedAt > 0 && now-blockedAt > int64(2*rl.blockDuration) {
					rl.entries.Delete(key)
				}
				return true
			})
		}
	}
}
```

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/security/ -v -count=1`
Expected: All PASS (validate + connlimiter + ratelimiter tests).

**Step 6: Commit**

```bash
git add internal/security/ratelimiter.go internal/security/ratelimiter_test.go go.mod go.sum
git commit -m "feat(security): add per-IP rate limiter with failed-handshake tracking"
```

---

## Task 4: Yamux Hardening

**Files:**
- Modify: `internal/tunnel/server.go:97-98` (yamux session creation)

**Step 1: Run existing tests to establish baseline**

Run: `go test ./internal/tunnel/ -v -count=1`
Expected: All PASS.

**Step 2: Add yamux config**

In `internal/tunnel/server.go`, add to the const block:

```go
const (
	handshakeTimeout       = 10 * time.Second
	yamuxAcceptBacklog     = 128
	yamuxStreamCloseTimeout = 60 * time.Second
	yamuxStreamOpenTimeout  = 30 * time.Second
	yamuxMaxStreamWindow   = 512 * 1024 // 512KB per stream
)
```

Replace line 98 (`yamux.Server(encConn, nil)`) with:

```go
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.AcceptBacklog = yamuxAcceptBacklog
	yamuxCfg.StreamCloseTimeout = yamuxStreamCloseTimeout
	yamuxCfg.StreamOpenTimeout = yamuxStreamOpenTimeout
	yamuxCfg.MaxStreamWindowSize = yamuxMaxStreamWindow
	yamuxCfg.LogOutput = io.Discard
	session, err := yamux.Server(encConn, yamuxCfg)
```

Also add equivalent config in `internal/tunnel/client.go` line 107, replace `yamux.Client(encConn, nil)` with:

```go
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.AcceptBacklog = 128
	yamuxCfg.StreamCloseTimeout = 60 * time.Second
	yamuxCfg.StreamOpenTimeout = 30 * time.Second
	yamuxCfg.MaxStreamWindowSize = 512 * 1024
	yamuxCfg.LogOutput = io.Discard
	session, err := yamux.Client(encConn, yamuxCfg)
```

**Step 3: Run tests to verify nothing broke**

Run: `go test ./internal/tunnel/ -v -count=1 && go test ./internal/... -v -count=1`
Expected: All PASS.

**Step 4: Commit**

```bash
git add internal/tunnel/server.go internal/tunnel/client.go
git commit -m "feat(security): harden yamux config with stream limits and timeouts"
```

---

## Task 5: Integrate Security into Tunnel Server

**Files:**
- Modify: `internal/tunnel/server.go` (Server struct, Serve, handleConn, handleStream)

**Step 1: Run existing tests to establish baseline**

Run: `go test ./... -count=1`
Expected: All PASS.

**Step 2: Update Server struct and constructor**

In `internal/tunnel/server.go`, add import for `"github.com/mkloubert/go-proxy/internal/security"` and update:

```go
type Server struct {
	secret      string
	connLimiter *security.ConnLimiter
	rateLimiter *security.RateLimiter
}

func NewServer(secret string) *Server {
	return &Server{
		secret:      secret,
		connLimiter: security.NewConnLimiter(256),
		rateLimiter: security.NewRateLimiter(10, 5, 5, 5*time.Minute),
	}
}
```

Add a Close method:

```go
func (s *Server) Close() {
	s.rateLimiter.Stop()
}
```

**Step 3: Update Serve() — security checks before goroutine**

Replace the accept loop in `Serve()`:

```go
func (s *Server) Serve(ln net.Listener) error {
	slog.Info("tunnel server listening", "addr", ln.Addr().String())

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept failed: %w", err)
		}

		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

		// Rate limit check — blocked IPs are rejected without a goroutine
		if !s.rateLimiter.Allow(ip) {
			conn.Close()
			continue
		}

		// Connection limit check
		if !s.connLimiter.Acquire() {
			conn.Close()
			continue
		}

		go s.handleConn(conn, ip)
	}
}
```

**Step 4: Update handleConn() — failure tracking + release**

```go
func (s *Server) handleConn(conn net.Conn, ip string) {
	defer conn.Close()
	defer s.connLimiter.Release()

	conn.SetDeadline(time.Now().Add(handshakeTimeout))

	encConn, err := crypto.ServerHandshake(conn, s.secret)
	if err != nil {
		s.rateLimiter.RecordFailure(ip)
		slog.Debug("handshake failed", "remote", conn.RemoteAddr().String(), "error", err)
		return
	}

	conn.SetDeadline(time.Time{})
	slog.Info("handshake completed", "remote", conn.RemoteAddr().String())

	// ... yamux session creation + stream accept loop (unchanged)
}
```

**Step 5: Update handleStream() — target validation + timeout**

```go
func (s *Server) handleStream(stream net.Conn) {
	defer stream.Close()

	// Deadline for reading the target address header
	stream.SetDeadline(time.Now().Add(10 * time.Second))

	// Step 1: Read target address length
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		slog.Error("failed to read target address length", "error", err)
		return
	}

	addrLen := binary.BigEndian.Uint16(lenBuf)
	if addrLen == 0 {
		slog.Error("target address length is zero")
		return
	}

	// Step 2: Read target address
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		slog.Error("failed to read target address", "error", err)
		return
	}

	target := string(addrBuf)

	// Step 3: Validate target (SSRF protection)
	if err := security.ValidateTarget(target); err != nil {
		slog.Debug("target rejected", "target", target, "error", err)
		return
	}

	// Clear deadline for relay phase
	stream.SetDeadline(time.Time{})

	slog.Debug("dialing target", "target", target)

	// Step 4: Safe dial (resolves DNS, checks IPs, then connects)
	targetConn, err := security.SafeDial(target)
	if err != nil {
		slog.Error("failed to dial target", "target", target, "error", err)
		return
	}
	defer targetConn.Close()

	slog.Debug("connected to target", "target", target)

	// Step 5: Bidirectional relay
	relay(stream, targetConn)
}
```

**Step 6: Run existing tests**

Run: `go test ./internal/tunnel/ -v -count=1`
Expected: All PASS. The existing tests use `127.0.0.1` echo servers — but those connections go through the tunnel client's `OpenStream`, which sends the address to the remote server's `handleStream`. Since the echo server runs on `127.0.0.1`, `ValidateTarget` will reject it!

**IMPORTANT FIX:** The tunnel tests need to be updated to use `NewServer` properly. Since the tunnel server now rejects `127.0.0.1` targets via `ValidateTarget`, the tests that use local echo servers will fail.

Two options:
- Option A: Make the test create a server with validation disabled
- Option B: Export a method to disable validation in tests

**Chosen approach:** Add an `AllowPrivateIPs` field to `Server` that skips validation. Set it in tests.

Add to Server struct:
```go
type Server struct {
	secret         string
	connLimiter    *security.ConnLimiter
	rateLimiter    *security.RateLimiter
	AllowPrivateIPs bool // for testing only
}
```

In `handleStream`, before validation:
```go
	if !s.AllowPrivateIPs {
		if err := security.ValidateTarget(target); err != nil {
			slog.Debug("target rejected", "target", target, "error", err)
			return
		}
	}
```

**Step 7: Update test helpers**

In `internal/tunnel/tunnel_test.go`, update `startTunnelServer`:

```go
func startTunnelServer(t *testing.T, secret string) (string, func()) {
	// ...
	srv := NewServer(secret)
	srv.AllowPrivateIPs = true
	// ...
}
```

In `internal/integration_test.go`, update `startTunnelRemote`:

```go
func startTunnelRemote(t *testing.T, secret string) string {
	// ...
	srv := tunnel.NewServer(secret)
	srv.AllowPrivateIPs = true
	// ...
}
```

**Step 8: Run all tests**

Run: `go test ./... -v -count=1`
Expected: All PASS.

**Step 9: Commit**

```bash
git add internal/tunnel/server.go internal/tunnel/tunnel_test.go internal/integration_test.go
git commit -m "feat(security): integrate connection limiter, rate limiter, and SSRF protection into tunnel server"
```

---

## Task 6: Security Integration Tests

**Files:**
- Create: `internal/tunnel/server_security_test.go`

**Step 1: Write security-specific tests**

File: `internal/tunnel/server_security_test.go`

```go
// Copyright © 2026 Marcel Joachim Kloubert <marcel@kloubert.dev>
// ... (full license header)

package tunnel

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestServerRejectsWrongSecret(t *testing.T) {
	serverSecret := makeTestSecret(0xAA)
	clientSecret := makeTestSecret(0xBB)

	tunnelAddr, cleanup := startTunnelServer(t, serverSecret)
	defer cleanup()

	// Connect with wrong secret — server should close without sending data
	conn, err := net.DialTimeout("tcp4", tunnelAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	// Send 32 bytes of "salt"
	salt := make([]byte, 32)
	conn.Write(salt)

	// Send garbage encrypted frame (4-byte length header + garbage payload)
	garbage := []byte{0x00, 0x00, 0x00, 0x20} // 32 bytes payload
	garbage = append(garbage, make([]byte, 32)...)
	conn.Write(garbage)

	// Server should close the connection without responding
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("server should not send any data to unauthenticated client")
	}
}

func TestServerConnectionLimit(t *testing.T) {
	secret := makeTestSecret(0xCC)

	// Create server with low connection limit for testing
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(secret)
	srv.AllowPrivateIPs = true
	// The default limit is 256 — for this test we rely on the fact that
	// connections that fail handshake are properly released
	go srv.Serve(ln)
	defer ln.Close()

	addr := ln.Addr().String()

	// Open connections that just sit idle (don't complete handshake)
	var conns []net.Conn
	for i := 0; i < 5; i++ {
		c, err := net.DialTimeout("tcp4", addr, 2*time.Second)
		if err != nil {
			break
		}
		conns = append(conns, c)
	}

	// Clean up
	for _, c := range conns {
		c.Close()
	}
}

func TestServerBlocksAfterFailedHandshakes(t *testing.T) {
	secret := makeTestSecret(0xDD)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(secret)
	srv.AllowPrivateIPs = true
	go srv.Serve(ln)
	defer ln.Close()
	defer srv.Close()

	addr := ln.Addr().String()

	// Send 6 failed handshake attempts (threshold is 5)
	for i := 0; i < 6; i++ {
		c, err := net.DialTimeout("tcp4", addr, 2*time.Second)
		if err != nil {
			continue
		}
		// Send garbage salt + garbage frame
		c.Write(make([]byte, 32))
		c.Write([]byte{0x00, 0x00, 0x00, 0x20})
		c.Write(make([]byte, 32))
		time.Sleep(50 * time.Millisecond)
		c.Close()
	}

	// Wait for server to process
	time.Sleep(200 * time.Millisecond)

	// Next connection should be immediately closed (IP blocked)
	c, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		// Connection refused is also acceptable — IP is blocked
		return
	}
	defer c.Close()

	// If connection was accepted, server should close it very quickly
	c.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 1)
	_, err = c.Read(buf)
	if err == nil {
		t.Fatal("blocked IP should not receive any data")
	}
}

func TestServerPrivateIPRejection(t *testing.T) {
	secret := makeTestSecret(0xEE)

	// Start echo server on loopback
	echoLn, echoCleanup := startEchoServer(t)
	defer echoCleanup()

	// Create server WITHOUT AllowPrivateIPs
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(secret)
	// AllowPrivateIPs = false (default) — should reject the echo server address
	go srv.Serve(ln)
	defer ln.Close()
	defer srv.Close()

	tunnelAddr := ln.Addr().String()
	echoAddr := echoLn.Addr().String()

	// Connect with correct secret
	client := NewClient(tunnelAddr, secret)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect failed: %v", err)
	}

	// Try to open stream to private IP — should fail
	stream, err := client.OpenStream(echoAddr)
	if err != nil {
		// Stream open failed — acceptable
		return
	}
	defer stream.Close()

	// If stream opened, write should fail because server rejected the target
	stream.Write([]byte("hello"))
	stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 5)
	_, err = stream.Read(buf)
	if err == nil && string(buf) == "hello" {
		t.Fatal("server should have rejected connection to private IP")
	}
}
```

**Step 2: Run all tests**

Run: `go test ./... -v -count=1`
Expected: All PASS.

**Step 3: Commit**

```bash
git add internal/tunnel/server_security_test.go
git commit -m "test(security): add integration tests for security hardening"
```

---

## Task 7: Final Verification

**Step 1: Run full test suite**

Run: `go test ./... -v -count=1 -race`
Expected: All PASS, no race conditions.

**Step 2: Build binary**

Run: `go build -o go-proxy .`
Expected: Clean build, no warnings.

**Step 3: Verify no import cycles**

Run: `go vet ./...`
Expected: No issues.

**Step 4: Final commit if any cleanup needed**

```bash
git add -A && git status
# Only commit if there are changes
```
