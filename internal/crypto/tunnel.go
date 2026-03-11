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

package crypto

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

// EncryptedConn wraps a net.Conn with AES-256-GCM encryption and optional
// zstd compression. It implements the net.Conn interface.
//
// Framing protocol:
//
//	[4 bytes: bit 31 = compressed flag, bits 0-30 = length of nonce+ciphertext (big-endian)]
//	[12 bytes: nonce (prefix + counter)]
//	[N bytes: AES-256-GCM ciphertext + 16-byte auth tag]
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
	closeOnce    sync.Once
	closeErr     error
}

// NewEncryptedConn creates a new EncryptedConn wrapping the given connection
// with the specified AES-256 encryption key and nonce prefix for writes.
func NewEncryptedConn(conn net.Conn, key, noncePrefix []byte) (*EncryptedConn, error) {
	if len(key) != EncryptionKeySize {
		return nil, fmt.Errorf("invalid key size: expected %d bytes, got %d", EncryptionKeySize, len(key))
	}

	if len(noncePrefix) != NoncePrefixSize {
		return nil, fmt.Errorf("invalid nonce prefix size: expected %d bytes, got %d", NoncePrefixSize, len(noncePrefix))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	prefix := make([]byte, NoncePrefixSize)
	copy(prefix, noncePrefix)

	zstdEnc, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd encoder: %w", err)
	}

	zstdDec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(MaxFrameSize*2))
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd decoder: %w", err)
	}

	return &EncryptedConn{
		conn:        conn,
		gcm:         gcm,
		noncePrefix: prefix,
		zstdEnc:     zstdEnc,
		zstdDec:     zstdDec,
	}, nil
}

// Write encrypts data and writes it to the underlying connection.
// Large payloads are split into frames of at most MaxFrameSize bytes.
func (ec *EncryptedConn) Write(p []byte) (int, error) {
	ec.writeMu.Lock()
	defer ec.writeMu.Unlock()

	totalWritten := 0

	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > MaxFrameSize {
			chunkSize = MaxFrameSize
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]

		if err := ec.writeFrame(chunk); err != nil {
			return totalWritten, err
		}
		totalWritten += chunkSize
	}

	return totalWritten, nil
}

// writeFrame encrypts a single chunk and writes the framed data atomically.
func (ec *EncryptedConn) writeFrame(plaintext []byte) error {
	// Try to compress the plaintext
	compressed := ec.zstdEnc.EncodeAll(plaintext, nil)
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

// Read decrypts data from the underlying connection.
// If buffered plaintext is available from a previous frame, it is returned first.
func (ec *EncryptedConn) Read(p []byte) (int, error) {
	ec.readMu.Lock()
	defer ec.readMu.Unlock()

	// Return buffered data first
	if len(ec.readBuf) > 0 {
		n := copy(p, ec.readBuf)
		ec.readBuf = ec.readBuf[n:]
		return n, nil
	}

	// Read a new frame
	plaintext, err := ec.readFrame()
	if err != nil {
		return 0, err
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		ec.readBuf = plaintext[n:]
	}

	return n, nil
}

// readFrame reads and decrypts a single frame from the underlying connection.
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
		if len(decompressed) > MaxFrameSize {
			return nil, fmt.Errorf("decompressed frame too large: %d bytes (max %d)", len(decompressed), MaxFrameSize)
		}
		return decompressed, nil
	}

	return plaintext, nil
}

// Close releases compression resources and closes the underlying connection.
// It is safe to call Close multiple times; only the first call performs cleanup.
func (ec *EncryptedConn) Close() error {
	ec.closeOnce.Do(func() {
		var errs []error
		if ec.zstdEnc != nil {
			if err := ec.zstdEnc.Close(); err != nil {
				errs = append(errs, fmt.Errorf("zstd encoder close: %w", err))
			}
		}
		if ec.zstdDec != nil {
			ec.zstdDec.Close()
		}
		if err := ec.conn.Close(); err != nil {
			errs = append(errs, err)
		}
		ec.closeErr = errors.Join(errs...)
	})
	return ec.closeErr
}

// LocalAddr returns the local network address of the underlying connection.
func (ec *EncryptedConn) LocalAddr() net.Addr {
	return ec.conn.LocalAddr()
}

// RemoteAddr returns the remote network address of the underlying connection.
func (ec *EncryptedConn) RemoteAddr() net.Addr {
	return ec.conn.RemoteAddr()
}

// SetDeadline sets the deadline on the underlying connection.
func (ec *EncryptedConn) SetDeadline(t time.Time) error {
	return ec.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (ec *EncryptedConn) SetReadDeadline(t time.Time) error {
	return ec.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
func (ec *EncryptedConn) SetWriteDeadline(t time.Time) error {
	return ec.conn.SetWriteDeadline(t)
}

// CloseWrite signals that no more data will be written.
// Since WebSocket connections don't support TCP half-close,
// this closes the entire underlying connection to unblock
// any pending reads on the other direction.
func (ec *EncryptedConn) CloseWrite() error {
	return ec.conn.Close()
}

// Verify EncryptedConn implements net.Conn at compile time.
var _ net.Conn = (*EncryptedConn)(nil)
