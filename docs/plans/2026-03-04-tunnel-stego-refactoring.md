# Tunnel Steganography Refactoring Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the raw TCP tunnel transport with HTTP/1.1-based communication using PNG steganography, so the tunnel works through restrictive corporate proxies that perform TLS MITM.

**Architecture:** The tunnel disguises itself as an image gallery REST API. Encrypted data is hidden in valid PNG images via 2-LSB steganography. A `StegoConn` adapter implements `net.Conn` over HTTP POST requests, allowing yamux and `EncryptedConn` to sit on top unchanged. The remote side becomes an `net/http` server instead of a raw TCP listener.

**Tech Stack:** Go standard library (`image/png`, `net/http`, `crypto/rand`), hashicorp/yamux (unchanged), google/uuid (new dependency), existing AES-256-GCM crypto package.

**Design doc:** `/workspace/TUNNEL-REFACTORING.md`

**License header** (required on every new `.go` file):
```
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
```

---

## Task 1: Carrier Image Generation (`internal/stego/carrier.go`)

**Files:**
- Create: `internal/stego/carrier.go`
- Test: `internal/stego/carrier_test.go`

**Step 1: Write the failing test**

Create `internal/stego/carrier_test.go`:

```go
// <license header>

package stego

import (
	"image"
	"testing"
)

func TestGenerateCarrier_ReturnsCorrectDimensions(t *testing.T) {
	img := GenerateCarrier(256, 256)
	if img == nil {
		t.Fatal("GenerateCarrier returned nil")
	}
	bounds := img.Bounds()
	if bounds.Dx() != 256 || bounds.Dy() != 256 {
		t.Fatalf("expected 256x256, got %dx%d", bounds.Dx(), bounds.Dy())
	}
}

func TestGenerateCarrier_AllPixelsHaveFullAlpha(t *testing.T) {
	img := GenerateCarrier(64, 64)
	bounds := img.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			_, _, _, a := img.At(x, y).RGBA()
			if a>>8 != 255 {
				t.Fatalf("pixel (%d,%d) has alpha %d, expected 255", x, y, a>>8)
			}
		}
	}
}

func TestGenerateCarrier_TwoCallsProduceDifferentImages(t *testing.T) {
	img1 := GenerateCarrier(64, 64)
	img2 := GenerateCarrier(64, 64)
	// Compare a sample of pixels — they should differ due to random seed
	same := 0
	bounds := img1.Bounds()
	total := bounds.Dx() * bounds.Dy()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r1, g1, b1, _ := img1.At(x, y).RGBA()
			r2, g2, b2, _ := img2.At(x, y).RGBA()
			if r1 == r2 && g1 == g2 && b1 == b2 {
				same++
			}
		}
	}
	// With random seeds, less than 5% of pixels should match
	if float64(same)/float64(total) > 0.05 {
		t.Fatalf("images too similar: %d/%d pixels identical", same, total)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /workspace && go test ./internal/stego/ -v -run TestGenerateCarrier`
Expected: FAIL — package does not exist yet.

**Step 3: Write minimal implementation**

Create `internal/stego/carrier.go`:

```go
// <license header>

package stego

import (
	"crypto/rand"
	"encoding/binary"
	"image"
	"image/color"
	mrand "math/rand"
)

// GenerateCarrier creates a procedurally generated RGBA image of the given
// dimensions. The image uses smooth gradients with random noise to produce
// natural-looking content. Each call uses a cryptographically random seed,
// producing a unique image every time.
func GenerateCarrier(width, height int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	seed := make([]byte, 8)
	rand.Read(seed)
	rng := mrand.New(mrand.NewSource(int64(binary.BigEndian.Uint64(seed))))

	// Random base colors for gradient corners
	baseR := rng.Intn(200) + 20
	baseG := rng.Intn(200) + 20
	baseB := rng.Intn(200) + 20

	for y := 0; y < height; y++ {
		fy := float64(y) / float64(height)
		for x := 0; x < width; x++ {
			fx := float64(x) / float64(width)

			// Gradient based on position
			gr := float64(baseR) * (1.0 - fx*0.3 - fy*0.3)
			gg := float64(baseG) * (1.0 - fx*0.2 + fy*0.2)
			gb := float64(baseB) * (1.0 + fx*0.2 - fy*0.3)

			// Add noise
			r := clampUint8(int(gr) + rng.Intn(30) - 15)
			g := clampUint8(int(gg) + rng.Intn(30) - 15)
			b := clampUint8(int(gb) + rng.Intn(30) - 15)

			img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
		}
	}
	return img
}

func clampUint8(v int) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}
```

**Step 4: Run test to verify it passes**

Run: `cd /workspace && go test ./internal/stego/ -v -run TestGenerateCarrier`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/stego/carrier.go internal/stego/carrier_test.go
git commit -m "feat(stego): add procedural carrier image generation"
```

---

## Task 2: LSB Steganography Embed/Extract (`internal/stego/embed.go`)

**Files:**
- Create: `internal/stego/embed.go`
- Modify: `internal/stego/carrier_test.go` → add new tests in a new test file
- Test: `internal/stego/embed_test.go`

**Step 1: Write the failing tests**

Create `internal/stego/embed_test.go`:

```go
// <license header>

package stego

import (
	"bytes"
	"testing"
)

func TestRequiredImageSize_SmallPayload(t *testing.T) {
	// 100 bytes needs ceil(100*8/6) = 134 pixels → 16x16 = 256 pixels (min)
	w, h := RequiredImageSize(100)
	if w < 16 || h < 16 {
		t.Fatalf("image too small for 100 bytes: %dx%d", w, h)
	}
	capacity := w * h * 6 / 8
	if capacity < 100+4 { // 4 bytes length header
		t.Fatalf("capacity %d too small for 100+4 bytes", capacity)
	}
}

func TestRequiredImageSize_LargePayload(t *testing.T) {
	w, h := RequiredImageSize(192 * 1024) // needs 512x512
	if w < 512 || h < 512 {
		t.Fatalf("image too small for 192KB: %dx%d", w, h)
	}
}

func TestEmbedExtract_Roundtrip(t *testing.T) {
	data := []byte("hello steganography world! this is a secret message.")
	carrier := GenerateCarrier(256, 256)

	pngData, err := Embed(carrier, data)
	if err != nil {
		t.Fatalf("Embed failed: %v", err)
	}

	// Verify it starts with PNG signature
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if !bytes.HasPrefix(pngData, pngSig) {
		t.Fatal("output is not a valid PNG (missing signature)")
	}

	extracted, err := Extract(pngData)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if !bytes.Equal(data, extracted) {
		t.Fatalf("roundtrip mismatch:\n  got:  %q\n  want: %q", extracted, data)
	}
}

func TestEmbedExtract_EmptyPayload(t *testing.T) {
	carrier := GenerateCarrier(64, 64)
	pngData, err := Embed(carrier, []byte{})
	if err != nil {
		t.Fatalf("Embed empty failed: %v", err)
	}

	extracted, err := Extract(pngData)
	if err != nil {
		t.Fatalf("Extract empty failed: %v", err)
	}

	if len(extracted) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(extracted))
	}
}

func TestEmbedExtract_MaxCapacity(t *testing.T) {
	carrier := GenerateCarrier(256, 256)
	// 256*256 pixels * 6 bits / 8 = 49152 bytes capacity, minus 4 for header
	maxPayload := (256*256*6/8) - 4
	data := make([]byte, maxPayload)
	for i := range data {
		data[i] = byte(i % 251) // non-trivial pattern
	}

	pngData, err := Embed(carrier, data)
	if err != nil {
		t.Fatalf("Embed max capacity failed: %v", err)
	}

	extracted, err := Extract(pngData)
	if err != nil {
		t.Fatalf("Extract max capacity failed: %v", err)
	}

	if !bytes.Equal(data, extracted) {
		t.Fatal("max capacity roundtrip mismatch")
	}
}

func TestEmbed_PayloadTooLarge(t *testing.T) {
	carrier := GenerateCarrier(64, 64)
	// 64*64*6/8 = 3072 bytes capacity, minus 4 = 3068 max payload
	data := make([]byte, 4000)
	_, err := Embed(carrier, data)
	if err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /workspace && go test ./internal/stego/ -v -run "TestRequiredImageSize|TestEmbedExtract|TestEmbed_Payload"`
Expected: FAIL — `RequiredImageSize`, `Embed`, `Extract` not defined.

**Step 3: Write minimal implementation**

Create `internal/stego/embed.go`:

```go
// <license header>

package stego

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
)

const (
	// bitsPerPixel is the number of data bits embedded per pixel (2 LSBs * 3 RGB channels).
	bitsPerPixel = 6

	// lengthHeaderSize is the number of bytes used for the payload length prefix.
	lengthHeaderSize = 4

	// minDimension is the smallest carrier image dimension.
	minDimension = 16
)

// RequiredImageSize returns the minimum square image dimensions (width, height)
// needed to embed dataLen bytes of payload (plus 4-byte length header).
// Dimensions are rounded up to the next power of two.
func RequiredImageSize(dataLen int) (int, int) {
	totalBytes := dataLen + lengthHeaderSize
	totalBits := totalBytes * 8
	pixelsNeeded := int(math.Ceil(float64(totalBits) / float64(bitsPerPixel)))
	side := int(math.Ceil(math.Sqrt(float64(pixelsNeeded))))

	// Round up to next power of 2, minimum 16
	dim := minDimension
	for dim < side {
		dim *= 2
	}
	return dim, dim
}

// Capacity returns the maximum number of payload bytes that can be embedded
// in an image of the given dimensions (excluding the 4-byte length header).
func Capacity(width, height int) int {
	totalBits := width * height * bitsPerPixel
	totalBytes := totalBits / 8
	if totalBytes < lengthHeaderSize {
		return 0
	}
	return totalBytes - lengthHeaderSize
}

// Embed hides data in the carrier image using 2-LSB steganography on
// the R, G, B channels. It returns the resulting PNG-encoded image bytes.
// The alpha channel is not modified.
func Embed(carrier *image.RGBA, data []byte) ([]byte, error) {
	bounds := carrier.Bounds()
	width, height := bounds.Dx(), bounds.Dy()

	maxPayload := Capacity(width, height)
	if len(data) > maxPayload {
		return nil, fmt.Errorf("payload too large: %d bytes exceeds capacity %d bytes for %dx%d image",
			len(data), maxPayload, width, height)
	}

	// Prepend 4-byte big-endian length header
	header := make([]byte, lengthHeaderSize)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	payload := append(header, data...)

	// Convert payload to bit stream
	bits := bytesToBits(payload)
	bitIdx := 0

	// Clone the carrier so we don't modify the original
	out := image.NewRGBA(bounds)
	copy(out.Pix, carrier.Pix)

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, a := out.At(x, y).RGBA()

			// Get 2 bits per channel (6 bits total)
			rb1, rb0 := getBit(bits, bitIdx), getBit(bits, bitIdx+1)
			gb1, gb0 := getBit(bits, bitIdx+2), getBit(bits, bitIdx+3)
			bb1, bb0 := getBit(bits, bitIdx+4), getBit(bits, bitIdx+5)
			bitIdx += 6

			// Replace 2 LSBs of each channel
			nr := (uint8(r>>8) & 0xFC) | (rb1 << 1) | rb0
			ng := (uint8(g>>8) & 0xFC) | (gb1 << 1) | gb0
			nb := (uint8(b>>8) & 0xFC) | (bb1 << 1) | bb0

			out.SetRGBA(x, y, color.RGBA{R: nr, G: ng, B: nb, A: uint8(a >> 8)})
		}
	}

	// Encode as PNG with fast compression
	var buf bytes.Buffer
	enc := &png.Encoder{CompressionLevel: png.BestSpeed}
	if err := enc.Encode(&buf, out); err != nil {
		return nil, fmt.Errorf("PNG encode failed: %w", err)
	}

	return buf.Bytes(), nil
}

// Extract reads hidden data from a PNG image that was encoded with Embed.
func Extract(pngData []byte) ([]byte, error) {
	img, err := png.Decode(bytes.NewReader(pngData))
	if err != nil {
		return nil, fmt.Errorf("PNG decode failed: %w", err)
	}

	bounds := img.Bounds()
	var bits []byte

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()

			// Extract 2 LSBs from each channel
			bits = append(bits, uint8((r>>8)>>1)&1, uint8(r>>8)&1)
			bits = append(bits, uint8((g>>8)>>1)&1, uint8(g>>8)&1)
			bits = append(bits, uint8((b>>8)>>1)&1, uint8(b>>8)&1)
		}
	}

	// Read 4-byte length header (32 bits)
	if len(bits) < lengthHeaderSize*8 {
		return nil, fmt.Errorf("image too small to contain length header")
	}

	lengthBytes := bitsToBytes(bits[:lengthHeaderSize*8])
	payloadLen := binary.BigEndian.Uint32(lengthBytes)

	if payloadLen == 0 {
		return []byte{}, nil
	}

	totalBitsNeeded := (lengthHeaderSize + int(payloadLen)) * 8
	if len(bits) < totalBitsNeeded {
		return nil, fmt.Errorf("image too small for payload: need %d bits, have %d", totalBitsNeeded, len(bits))
	}

	data := bitsToBytes(bits[lengthHeaderSize*8 : totalBitsNeeded])
	return data, nil
}

// bytesToBits converts a byte slice to a slice of individual bits (0 or 1),
// MSB first within each byte.
func bytesToBits(data []byte) []byte {
	bits := make([]byte, len(data)*8)
	for i, b := range data {
		for j := 7; j >= 0; j-- {
			bits[i*8+(7-j)] = (b >> j) & 1
		}
	}
	return bits
}

// bitsToBytes converts a slice of individual bits back to bytes.
func bitsToBytes(bits []byte) []byte {
	n := len(bits) / 8
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			b = (b << 1) | (bits[i*8+j] & 1)
		}
		out[i] = b
	}
	return out
}

// getBit returns the bit at position idx from bits, or 0 if out of range.
func getBit(bits []byte, idx int) uint8 {
	if idx >= len(bits) {
		return 0
	}
	return bits[idx] & 1
}
```

**Step 4: Run test to verify it passes**

Run: `cd /workspace && go test ./internal/stego/ -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add internal/stego/embed.go internal/stego/embed_test.go
git commit -m "feat(stego): add LSB steganography embed/extract with 2-bit RGB encoding"
```

---

## Task 3: Add UUID Dependency

**Step 1: Add google/uuid**

Run: `cd /workspace && go get github.com/google/uuid`

**Step 2: Verify**

Run: `cd /workspace && grep google/uuid go.mod`
Expected: shows `github.com/google/uuid vX.X.X`

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add google/uuid dependency for gallery API paths"
```

---

## Task 4: Session Manager (`internal/transport/session.go`)

**Files:**
- Create: `internal/transport/session.go`
- Test: `internal/transport/session_test.go`

**Step 1: Write the failing tests**

Create `internal/transport/session_test.go`:

```go
// <license header>

package transport

import (
	"testing"
	"time"
)

func TestSessionManager_CreateAndGet(t *testing.T) {
	sm := NewSessionManager(60 * time.Second)
	defer sm.Stop()

	token, sess := sm.Create()
	if token == "" {
		t.Fatal("empty token")
	}
	if sess == nil {
		t.Fatal("nil session")
	}

	got := sm.Get(token)
	if got != sess {
		t.Fatal("Get returned different session")
	}
}

func TestSessionManager_GetInvalidToken(t *testing.T) {
	sm := NewSessionManager(60 * time.Second)
	defer sm.Stop()

	got := sm.Get("nonexistent-token")
	if got != nil {
		t.Fatal("expected nil for invalid token")
	}
}

func TestSessionManager_Remove(t *testing.T) {
	sm := NewSessionManager(60 * time.Second)
	defer sm.Stop()

	token, _ := sm.Create()
	sm.Remove(token)

	got := sm.Get(token)
	if got != nil {
		t.Fatal("session not removed")
	}
}

func TestSessionManager_Expiry(t *testing.T) {
	sm := NewSessionManager(50 * time.Millisecond)
	defer sm.Stop()

	token, _ := sm.Create()
	time.Sleep(150 * time.Millisecond)

	got := sm.Get(token)
	if got != nil {
		t.Fatal("expected session to be expired")
	}
}

func TestSessionManager_TouchPreventsExpiry(t *testing.T) {
	sm := NewSessionManager(100 * time.Millisecond)
	defer sm.Stop()

	token, sess := sm.Create()

	// Touch before expiry
	time.Sleep(60 * time.Millisecond)
	sess.Touch()

	time.Sleep(60 * time.Millisecond)
	got := sm.Get(token)
	if got == nil {
		t.Fatal("session should not have expired after touch")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /workspace && go test ./internal/transport/ -v -run TestSessionManager`
Expected: FAIL — package does not exist.

**Step 3: Write minimal implementation**

Create `internal/transport/session.go`:

```go
// <license header>

package transport

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Session represents an active tunnel session on the server side.
type Session struct {
	mu       sync.Mutex
	lastSeen time.Time

	// ReadCh receives upstream data extracted from incoming PNG requests.
	ReadCh chan []byte

	// WriteBuf collects downstream data to be embedded in the next PNG response.
	WriteBuf []byte
	WriteMu  sync.Mutex
}

// Touch updates the session's last-seen timestamp.
func (s *Session) Touch() {
	s.mu.Lock()
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

// LastSeen returns the time of the last activity.
func (s *Session) LastSeen() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeen
}

// SessionManager manages active tunnel sessions keyed by token.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	timeout  time.Duration
	stopCh   chan struct{}
}

// NewSessionManager creates a new SessionManager that expires sessions
// after the given timeout. It starts a background cleanup goroutine.
func NewSessionManager(timeout time.Duration) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
		timeout:  timeout,
		stopCh:   make(chan struct{}),
	}
	go sm.cleanupLoop()
	return sm
}

// Create generates a new session with a cryptographically random token.
func (sm *SessionManager) Create() (string, *Session) {
	token := generateToken()
	sess := &Session{
		lastSeen: time.Now(),
		ReadCh:   make(chan []byte, 64),
	}

	sm.mu.Lock()
	sm.sessions[token] = sess
	sm.mu.Unlock()

	return token, sess
}

// Get returns the session for the given token, or nil if not found.
func (sm *SessionManager) Get(token string) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[token]
}

// Remove deletes a session by token.
func (sm *SessionManager) Remove(token string) {
	sm.mu.Lock()
	delete(sm.sessions, token)
	sm.mu.Unlock()
}

// Stop stops the background cleanup goroutine.
func (sm *SessionManager) Stop() {
	close(sm.stopCh)
}

func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(sm.timeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-sm.stopCh:
			return
		case <-ticker.C:
			sm.cleanup()
		}
	}
}

func (sm *SessionManager) cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	for token, sess := range sm.sessions {
		if now.Sub(sess.LastSeen()) > sm.timeout {
			delete(sm.sessions, token)
		}
	}
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
```

**Step 4: Run test to verify it passes**

Run: `cd /workspace && go test ./internal/transport/ -v -run TestSessionManager`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add internal/transport/session.go internal/transport/session_test.go
git commit -m "feat(transport): add session manager with token-based lookup and expiry"
```

---

## Task 5: Rewrite Tunnel Server as HTTP Server (`internal/tunnel/server.go`)

**Files:**
- Rewrite: `internal/tunnel/server.go`
- Modify: `cmd/remote.go`

This is the core server refactoring. The server becomes an `net/http` server that handles PNG steganography requests.

**Step 1: Rewrite `internal/tunnel/server.go`**

Replace the entire file. The new server:
- Listens on HTTP instead of raw TCP
- Routes `POST /api/v1/galleries/{uuid}/pictures` to a handler
- Checks `Authorization` header: missing = handshake, present = data exchange
- Uses `stego.Extract()` to read incoming data from PNGs
- Uses `stego.Embed()` + `stego.GenerateCarrier()` to write response PNGs
- Creates a `net.Conn`-compatible pipe per session for yamux to sit on top of

Key interfaces used from existing code (unchanged):
- `crypto.ServerHandshake` logic adapted to single request/response
- `crypto.DeriveKeys`, `crypto.NewEncryptedConn`
- `security.IPFilter`, `security.RateLimiter`, `security.ConnLimiter`
- `security.SafeDial`, `security.ValidateTarget`

The `ServerStegoConn` is implemented as an `io.Pipe`-based bridge: the HTTP handler writes extracted upstream data to one end, yamux reads from the other. Yamux writes downstream data to a buffer that the HTTP handler drains into the response PNG.

**Step 2: Run existing tests (they should still compile)**

Run: `cd /workspace && go build ./...`
Expected: compiles without error

**Step 3: Commit**

```bash
git add internal/tunnel/server.go
git commit -m "feat(tunnel): rewrite server as HTTP gallery API with PNG steganography"
```

---

## Task 6: Rewrite Tunnel Client (`internal/tunnel/client.go`)

**Files:**
- Rewrite: `internal/tunnel/client.go`

The new client:
- Connects via HTTP POST instead of raw TCP dial
- Performs handshake by sending PNG with embedded salt+challenge to the gallery API
- Creates a `StegoConn` implementing `net.Conn` that internally POSTs PNGs and extracts response PNGs
- Wraps `StegoConn` in `EncryptedConn`, then in yamux — same as before

**Step 1: Rewrite `internal/tunnel/client.go`**

The `StegoConn` type is the core new component:
- `Write()`: buffers data, `sendLoop` goroutine flushes periodically by encoding into PNG and POSTing
- `Read()`: blocks until data arrives from a POST response (extracted from PNG)
- `Close()`: signals shutdown

**Step 2: Verify compilation**

Run: `cd /workspace && go build ./...`
Expected: compiles without error

**Step 3: Commit**

```bash
git add internal/tunnel/client.go
git commit -m "feat(tunnel): rewrite client with HTTP gallery API + StegoConn adapter"
```

---

## Task 7: Update Handshake for HTTP (`internal/crypto/handshake.go`)

**Files:**
- Modify: `internal/crypto/handshake.go`

Add new functions for HTTP-based handshake that work with byte slices instead of streaming `net.Conn`:

- `ClientHandshakePayload(secret string) (salt, encryptedChallenge, challengePlain []byte, keys *DerivedKeys, err error)` — generates the handshake request payload
- `ServerHandshakePayload(payload []byte, secret string) (encryptedResponse []byte, keys *DerivedKeys, err error)` — processes handshake and returns response payload
- `ClientVerifyHandshake(response []byte, challengePlain []byte, keys *DerivedKeys) error` — verifies server response

The existing `ClientHandshake` and `ServerHandshake` functions can remain for backward compatibility during testing, but are no longer used by the tunnel.

**Step 1: Add new functions to `internal/crypto/handshake.go`**

**Step 2: Run existing handshake tests**

Run: `cd /workspace && go test ./internal/crypto/ -v -run TestHandshake`
Expected: existing tests still pass

**Step 3: Commit**

```bash
git add internal/crypto/handshake.go
git commit -m "feat(crypto): add HTTP-compatible handshake payload functions"
```

---

## Task 8: Update CLI Commands (`cmd/local.go`, `cmd/remote.go`)

**Files:**
- Modify: `cmd/local.go` — `--connect-to` now accepts URL format (`http://host:port`)
- Modify: `cmd/remote.go` — start `net/http` server instead of raw TCP listener

**Step 1: Update `cmd/remote.go`**

- Remove `net.Listen("tcp4", ...)` and `srv.Serve(ln)` pattern
- Replace with `http.ListenAndServe(addr, tunnelHTTPHandler)`
- The tunnel server now exposes its HTTP handler

**Step 2: Update `cmd/local.go`**

- Change `--connect-to` description to indicate URL format
- Pass full URL to tunnel client instead of `host:port`

**Step 3: Verify build**

Run: `cd /workspace && go build ./...`
Expected: compiles

**Step 4: Commit**

```bash
git add cmd/local.go cmd/remote.go
git commit -m "feat(cmd): update CLI to use HTTP transport for tunnel"
```

---

## Task 9: Integration Tests (`internal/integration_test.go`)

**Files:**
- Rewrite: `internal/integration_test.go`

The test helpers need to be updated:
- `startTunnelRemote` now starts an HTTP server (using `httptest.NewServer` or manual `net/http`)
- `startTunnelClient` now connects via HTTP URL
- The three main tests (HTTP proxy, HTTPS CONNECT, SOCKS5) stay conceptually the same

**Step 1: Rewrite test helpers**

```go
func startTunnelRemote(t *testing.T, secret string) string {
    // Create tunnel server (now HTTP-based)
    srv := tunnel.NewServer(secret)
    srv.SetAllowPrivateIPs(true)

    // Start HTTP server
    httpSrv := httptest.NewServer(srv.Handler())
    t.Cleanup(func() {
        srv.Close()
        httpSrv.Close()
    })

    return httpSrv.URL
}

func startTunnelClient(t *testing.T, remoteURL, secret string) *tunnel.Client {
    client := tunnel.NewClient(remoteURL, secret)
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := client.Connect(ctx); err != nil {
        t.Fatalf("tunnel client connect failed: %v", err)
    }

    t.Cleanup(func() { client.Close() })
    return client
}
```

**Step 2: Run all integration tests**

Run: `cd /workspace && go test ./internal/ -v -timeout 60s`
Expected: ALL PASS

**Step 3: Commit**

```bash
git add internal/integration_test.go
git commit -m "test: rewrite integration tests for HTTP+stego tunnel"
```

---

## Task 10: Full Test Suite + Cleanup

**Step 1: Run entire test suite**

Run: `cd /workspace && go test ./... -v -timeout 120s`
Expected: ALL PASS

**Step 2: Run go vet and build**

Run: `cd /workspace && go vet ./... && go build ./...`
Expected: no errors

**Step 3: Remove any dead code**

Check if old TCP-only code paths in `internal/tunnel/` are still referenced. Remove unused imports, unused functions.

**Step 4: Commit**

```bash
git add -A
git commit -m "chore: cleanup dead code from TCP tunnel removal"
```

---

## Task 11: Update TASKS.md and MILESTONE.md

**Files:**
- Modify: `TASKS.md`
- Modify: `MILESTONE.md` (if applicable)

**Step 1: Update TASKS.md with completed checklist**

Add a new section for the tunnel refactoring milestone with all phases checked off.

**Step 2: Commit**

```bash
git add TASKS.md MILESTONE.md
git commit -m "docs: update tasks and milestone for tunnel stego refactoring"
```

---

## Task 12: Update README.md

**Files:**
- Modify: `README.md`

**Step 1: Update usage examples**

Change the remote command example from TCP to HTTP:
```bash
# Before:
go-proxy remote --port=9876

# After:
go-proxy remote --port=80
```

Change the local command example:
```bash
# Before:
go-proxy local --port=12345 --connect-to="example.com:9876"

# After:
go-proxy local --port=12345 --connect-to="http://example.com:80"
```

Add a note explaining that the tunnel uses HTTP with image steganography for maximum compatibility with corporate proxies.

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: update README with HTTP tunnel usage and stego explanation"
```
