# zstd Frame-Level Compression Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add transparent zstd compression at the frame level inside `EncryptedConn`, compressing data before encryption and decompressing after decryption, with per-frame decision to skip compression when it does not reduce size.

**Architecture:** Use bit 31 of the existing 4-byte frame length header as a compression flag. The `writeFrame()` method compresses plaintext with zstd, only using the compressed form when it is smaller. The `readFrame()` method masks bit 31 to get the real length, then decompresses after decryption if the flag was set. Encoder and decoder are created once per `EncryptedConn` and reused across all frames.

**Tech Stack:** Go 1.25, `github.com/klauspost/compress/zstd` for Zstandard compression, existing AES-256-GCM encryption layer.

---

### Task 1: Add zstd dependency

**Files:**
- Modify: `go.mod`

**Step 1: Install the zstd dependency**

Run:
```bash
cd /workspace && go get github.com/klauspost/compress/zstd@latest
```

**Step 2: Verify the dependency is in go.mod**

Run:
```bash
grep klauspost /workspace/go.mod
```

Expected: A line containing `github.com/klauspost/compress`

---

### Task 2: Write failing tests for compression roundtrip

**Files:**
- Modify: `internal/crypto/tunnel_test.go`

**Step 1: Write failing tests**

Add these test functions to `internal/crypto/tunnel_test.go`:

```go
func TestEncryptedConnCompressibleData(t *testing.T) {
	encA, encB := createEncryptedPipe(t)
	defer encA.Close()
	defer encB.Close()

	// Highly compressible data (repeated text)
	message := []byte(strings.Repeat("Hello, this is compressible text data! ", 100))

	errCh := make(chan error, 1)
	go func() {
		_, err := encA.Write(message)
		errCh <- err
	}()

	received := make([]byte, 0, len(message))
	buf := make([]byte, 4096)
	for len(received) < len(message) {
		n, err := encB.Read(buf)
		if err != nil {
			t.Fatalf("Read returned error after %d bytes: %v", len(received), err)
		}
		received = append(received, buf[:n]...)
	}

	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("Write returned error: %v", writeErr)
	}

	if !bytes.Equal(received, message) {
		t.Error("received payload does not match sent payload")
	}
}

func TestEncryptedConnIncompressibleData(t *testing.T) {
	encA, encB := createEncryptedPipe(t)
	defer encA.Close()
	defer encB.Close()

	// Random data is not compressible
	message := make([]byte, 4096)
	if _, err := rand.Read(message); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := encA.Write(message)
		errCh <- err
	}()

	received := make([]byte, 0, len(message))
	buf := make([]byte, 4096)
	for len(received) < len(message) {
		n, err := encB.Read(buf)
		if err != nil {
			t.Fatalf("Read returned error after %d bytes: %v", len(received), err)
		}
		received = append(received, buf[:n]...)
	}

	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("Write returned error: %v", writeErr)
	}

	if !bytes.Equal(received, message) {
		t.Error("received payload does not match sent payload")
	}
}

func TestEncryptedConnEmptyFrame(t *testing.T) {
	encA, encB := createEncryptedPipe(t)
	defer encA.Close()
	defer encB.Close()

	message := []byte{}

	errCh := make(chan error, 1)
	go func() {
		_, err := encA.Write(message)
		errCh <- err
	}()

	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("Write returned error: %v", writeErr)
	}
}

func TestEncryptedConnMixedData(t *testing.T) {
	encA, encB := createEncryptedPipe(t)
	defer encA.Close()
	defer encB.Close()

	messages := [][]byte{
		[]byte(strings.Repeat("compressible text data ", 50)),
		make([]byte, 2048), // will be filled with random
		[]byte(strings.Repeat(`{"key":"value","data":"repeated"}`, 40)),
		make([]byte, 1024), // will be filled with random
	}
	// Fill random data
	rand.Read(messages[1])
	rand.Read(messages[3])

	for i, msg := range messages {
		errCh := make(chan error, 1)
		go func() {
			_, err := encA.Write(msg)
			errCh <- err
		}()

		received := make([]byte, 0, len(msg))
		buf := make([]byte, 4096)
		for len(received) < len(msg) {
			n, err := encB.Read(buf)
			if err != nil {
				t.Fatalf("message %d: Read returned error after %d bytes: %v", i, len(received), err)
			}
			received = append(received, buf[:n]...)
		}

		if writeErr := <-errCh; writeErr != nil {
			t.Fatalf("message %d: Write returned error: %v", i, writeErr)
		}

		if !bytes.Equal(received, msg) {
			t.Errorf("message %d: received payload does not match sent payload", i)
		}
	}
}

func TestEncryptedConnLargeCompressiblePayload(t *testing.T) {
	encA, encB := createEncryptedPipe(t)
	defer encA.Close()
	defer encB.Close()

	// Large payload that spans multiple frames (>MaxFrameSize), highly compressible
	payload := []byte(strings.Repeat("A", MaxFrameSize+10000))

	errCh := make(chan error, 1)
	go func() {
		_, err := encA.Write(payload)
		errCh <- err
	}()

	received := make([]byte, 0, len(payload))
	buf := make([]byte, 4096)
	for len(received) < len(payload) {
		n, err := encB.Read(buf)
		if err != nil {
			t.Fatalf("Read returned error after %d bytes: %v", len(received), err)
		}
		received = append(received, buf[:n]...)
	}

	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("Write returned error: %v", writeErr)
	}

	if !bytes.Equal(received, payload) {
		t.Error("received payload does not match sent payload")
	}
}

func TestEncryptedConnCompressedBitFrameRejection(t *testing.T) {
	// Verify that a frame with bit 31 set but invalid compressed data
	// is properly rejected (decompression error, not misinterpreted as length)
	connA, connB := net.Pipe()
	defer connA.Close()
	defer connB.Close()

	key := make([]byte, EncryptionKeySize)
	prefix := make([]byte, NoncePrefixSize)
	rand.Read(key)
	rand.Read(prefix)

	encA, err := NewEncryptedConn(connA, key, prefix)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn A: %v", err)
	}

	encB, err := NewEncryptedConn(connB, key, prefix)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn B: %v", err)
	}

	// Manually craft a frame with compression bit set but invalid zstd data
	go func() {
		nonce := make([]byte, gcmNonceSize)
		copy(nonce[:NoncePrefixSize], prefix)
		binary.BigEndian.PutUint64(nonce[NoncePrefixSize:], 1)

		// "plaintext" is garbage (not valid zstd)
		garbage := []byte("this is not valid zstd compressed data!!")
		ciphertext := encA.gcm.Seal(nil, nonce, garbage, nil)

		framePayloadLen := uint32(len(nonce) + len(ciphertext))
		framePayloadLen |= compressedBit // Set compression flag

		header := make([]byte, frameHeaderSize)
		binary.BigEndian.PutUint32(header, framePayloadLen)

		connA.Write(header)
		connA.Write(nonce)
		connA.Write(ciphertext)
	}()

	buf := make([]byte, 1024)
	_, err = encB.Read(buf)
	if err == nil {
		t.Fatal("expected decompression error, got nil")
	}
	if !strings.Contains(err.Error(), "decompression failed") {
		t.Fatalf("expected 'decompression failed' error, got: %v", err)
	}
}
```

**Step 2: Run tests to verify they fail**

Run:
```bash
cd /workspace && go test ./internal/crypto/ -run "TestEncryptedConn(Compressible|Incompressible|EmptyFrame|MixedData|LargeCompressible|CompressedBit)" -v -count=1
```

Expected: Compilation errors because `compressedBit` is not yet defined and `NewEncryptedConn` does not create zstd encoder/decoder yet.

---

### Task 3: Implement zstd compression in EncryptedConn

**Files:**
- Modify: `internal/crypto/tunnel.go:21-93` (imports, constants, struct, constructor)
- Modify: `internal/crypto/tunnel.go:121-144` (writeFrame)
- Modify: `internal/crypto/tunnel.go:174-209` (readFrame)
- Modify: `internal/crypto/tunnel.go:211-214` (Close)

**Step 1: Add zstd import and compressedBit constant**

In `internal/crypto/tunnel.go`, add the zstd import to the import block:

```go
import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)
```

Add the `compressedBit` constant after the existing constants:

```go
const (
	// MaxFrameSize is the maximum plaintext size per encrypted frame.
	MaxFrameSize = 65536

	// frameHeaderSize is the size of the frame length header in bytes (uint32 big-endian).
	frameHeaderSize = 4

	// gcmNonceSize is the standard GCM nonce size (12 bytes).
	gcmNonceSize = 12

	// compressedBit is the highest bit in the frame length header.
	// When set, the plaintext payload was zstd-compressed before encryption.
	compressedBit = uint32(1 << 31)
)
```

**Step 2: Add zstd fields to EncryptedConn struct**

Update the struct to:

```go
type EncryptedConn struct {
	conn         net.Conn
	gcm          cipher.AEAD
	writeMu      sync.Mutex
	readMu       sync.Mutex
	readBuf      []byte // buffered plaintext from previous Read
	noncePrefix  []byte
	writeCounter uint64
	zstdEnc      *zstd.Encoder
	zstdDec      *zstd.Decoder
}
```

Update the doc comment for the framing protocol:

```go
// EncryptedConn wraps a net.Conn with AES-256-GCM encryption and optional
// zstd compression. It implements the net.Conn interface.
//
// Framing protocol:
//
//	[4 bytes: bit 31 = compressed flag, bits 0-30 = length of nonce+ciphertext (big-endian)]
//	[12 bytes: nonce (prefix + counter)]
//	[N bytes: AES-256-GCM ciphertext + 16-byte auth tag]
```

**Step 3: Update NewEncryptedConn to create zstd encoder/decoder**

After creating the GCM cipher and before the return statement, add:

```go
	zstdEnc, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd encoder: %w", err)
	}

	zstdDec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(MaxFrameSize*2))
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd decoder: %w", err)
	}
```

And update the return to include them:

```go
	return &EncryptedConn{
		conn:        conn,
		gcm:         gcm,
		noncePrefix: prefix,
		zstdEnc:     zstdEnc,
		zstdDec:     zstdDec,
	}, nil
```

**Step 4: Update writeFrame with compression**

Replace the entire `writeFrame` method:

```go
func (ec *EncryptedConn) writeFrame(plaintext []byte) error {
	// Try to compress the plaintext
	compressed := ec.zstdEnc.EncodeAll(plaintext, make([]byte, 0, len(plaintext)))
	isCompressed := len(compressed) < len(plaintext)

	payload := plaintext
	if isCompressed {
		payload = compressed
	}

	// Build counter-based nonce: noncePrefix (4 bytes) || counter (8 bytes big-endian)
	nonce := make([]byte, gcmNonceSize)
	copy(nonce[:NoncePrefixSize], ec.noncePrefix)
	ec.writeCounter++
	counter := ec.writeCounter
	binary.BigEndian.PutUint64(nonce[NoncePrefixSize:], counter)

	// Encrypt: ciphertext includes the auth tag
	ciphertext := ec.gcm.Seal(nil, nonce, payload, nil)

	// Assemble complete frame in a single buffer for atomic write
	framePayloadLen := len(nonce) + len(ciphertext)
	frame := make([]byte, frameHeaderSize+framePayloadLen)

	// Encode length with compression flag in bit 31
	lenField := uint32(framePayloadLen)
	if isCompressed {
		lenField |= compressedBit
	}
	binary.BigEndian.PutUint32(frame[:frameHeaderSize], lenField)
	copy(frame[frameHeaderSize:], nonce)
	copy(frame[frameHeaderSize+len(nonce):], ciphertext)

	if _, err := ec.conn.Write(frame); err != nil {
		return fmt.Errorf("failed to write frame: %w", err)
	}

	return nil
}
```

**Step 5: Update readFrame with decompression**

Replace the entire `readFrame` method:

```go
func (ec *EncryptedConn) readFrame() ([]byte, error) {
	// Read the 4-byte length header
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(ec.conn, header); err != nil {
		return nil, fmt.Errorf("failed to read frame header: %w", err)
	}

	rawLen := binary.BigEndian.Uint32(header)

	// Extract compression flag from bit 31, then mask it out for the real length
	isCompressed := (rawLen & compressedBit) != 0
	frameLen := rawLen &^ compressedBit

	if frameLen < uint32(gcmNonceSize)+uint32(ec.gcm.Overhead()) {
		return nil, errors.New("frame too small to contain nonce and auth tag")
	}

	// Upper-bound check to prevent allocation of oversized buffers
	maxFrameWithOverhead := uint32(MaxFrameSize) + uint32(gcmNonceSize) + uint32(ec.gcm.Overhead())
	if frameLen > maxFrameWithOverhead {
		return nil, fmt.Errorf("frame too large: %d bytes", frameLen)
	}

	// Read the frame payload (nonce + ciphertext + tag)
	framePayload := make([]byte, frameLen)
	if _, err := io.ReadFull(ec.conn, framePayload); err != nil {
		return nil, fmt.Errorf("failed to read frame payload: %w", err)
	}

	// Split nonce and ciphertext
	nonce := framePayload[:gcmNonceSize]
	ciphertext := framePayload[gcmNonceSize:]

	// Decrypt
	plaintext, err := ec.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt frame: %w", err)
	}

	// Decompress if the compression flag was set
	if isCompressed {
		decompressed, err := ec.zstdDec.DecodeAll(plaintext, nil)
		if err != nil {
			return nil, fmt.Errorf("decompression failed: %w", err)
		}
		return decompressed, nil
	}

	return plaintext, nil
}
```

**Step 6: Update Close to release zstd resources**

Replace the `Close` method:

```go
func (ec *EncryptedConn) Close() error {
	if ec.zstdEnc != nil {
		ec.zstdEnc.Close()
	}
	if ec.zstdDec != nil {
		ec.zstdDec.Close()
	}
	return ec.conn.Close()
}
```

---

### Task 4: Run all tests and verify

**Files:**
- None (test run only)

**Step 1: Run new compression tests**

Run:
```bash
cd /workspace && go test ./internal/crypto/ -run "TestEncryptedConn(Compressible|Incompressible|EmptyFrame|MixedData|LargeCompressible|CompressedBit)" -v -count=1
```

Expected: All 6 new tests PASS.

**Step 2: Run ALL existing tests to verify no regressions**

Run:
```bash
cd /workspace && go test ./internal/crypto/ -v -count=1
```

Expected: All tests PASS (both new and existing).

**Step 3: Run full project test suite**

Run:
```bash
cd /workspace && go test ./... -count=1
```

Expected: All tests PASS across the entire project.

---

### Task 5: Verify the existing frame-size-limit test still works

**Files:**
- Modify: `internal/crypto/tunnel_test.go` (update existing test)

**Step 1: Check TestEncryptedConnFrameSizeLimit**

The existing `TestEncryptedConnFrameSizeLimit` test sends `0xFFFFFFFF` as a frame header. With the compression bit change, bit 31 would be interpreted as a compression flag, and the remaining bits (`0x7FFFFFFF`) would still be way too large and rejected by the "frame too large" check. The test should still pass as-is.

Run:
```bash
cd /workspace && go test ./internal/crypto/ -run TestEncryptedConnFrameSizeLimit -v -count=1
```

Expected: PASS. The frame is rejected because `0x7FFFFFFF` exceeds `maxFrameWithOverhead`.
