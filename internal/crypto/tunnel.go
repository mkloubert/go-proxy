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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// MaxFrameSize is the maximum plaintext size per encrypted frame.
	MaxFrameSize = 65536

	// frameHeaderSize is the size of the frame length header in bytes (uint32 big-endian).
	frameHeaderSize = 4

	// gcmNonceSize is the standard GCM nonce size (12 bytes).
	gcmNonceSize = 12
)

// EncryptedConn wraps a net.Conn with AES-256-GCM encryption.
// It implements the net.Conn interface.
//
// Framing protocol:
//
//	[4 bytes: length of nonce+ciphertext (big-endian)]
//	[12 bytes: nonce (random per frame)]
//	[N bytes: AES-256-GCM ciphertext + 16-byte auth tag]
type EncryptedConn struct {
	conn    net.Conn
	gcm     cipher.AEAD
	writeMu sync.Mutex
	readBuf []byte // buffered plaintext from previous Read
}

// NewEncryptedConn creates a new EncryptedConn wrapping the given connection
// with the specified AES-256 encryption key.
func NewEncryptedConn(conn net.Conn, key []byte) (*EncryptedConn, error) {
	if len(key) != EncryptionKeySize {
		return nil, fmt.Errorf("invalid key size: expected %d bytes, got %d", EncryptionKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &EncryptedConn{
		conn: conn,
		gcm:  gcm,
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

// writeFrame encrypts a single chunk and writes the framed data.
func (ec *EncryptedConn) writeFrame(plaintext []byte) error {
	// Generate a random nonce for this frame
	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt: nonce is prepended, ciphertext includes the auth tag
	ciphertext := ec.gcm.Seal(nil, nonce, plaintext, nil)

	// Frame: [4-byte length][nonce][ciphertext+tag]
	framePayload := make([]byte, 0, len(nonce)+len(ciphertext))
	framePayload = append(framePayload, nonce...)
	framePayload = append(framePayload, ciphertext...)

	// Write length header
	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint32(header, uint32(len(framePayload)))

	// Write header + payload
	if _, err := ec.conn.Write(header); err != nil {
		return fmt.Errorf("failed to write frame header: %w", err)
	}
	if _, err := ec.conn.Write(framePayload); err != nil {
		return fmt.Errorf("failed to write frame payload: %w", err)
	}

	return nil
}

// Read decrypts data from the underlying connection.
// If buffered plaintext is available from a previous frame, it is returned first.
func (ec *EncryptedConn) Read(p []byte) (int, error) {
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

	frameLen := binary.BigEndian.Uint32(header)
	if frameLen < uint32(gcmNonceSize)+uint32(ec.gcm.Overhead()) {
		return nil, errors.New("frame too small to contain nonce and auth tag")
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

	return plaintext, nil
}

// Close closes the underlying connection.
func (ec *EncryptedConn) Close() error {
	return ec.conn.Close()
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

// Verify EncryptedConn implements net.Conn at compile time.
var _ net.Conn = (*EncryptedConn)(nil)
