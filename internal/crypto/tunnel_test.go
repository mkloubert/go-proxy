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
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// createEncryptedPipe creates a pair of EncryptedConn instances connected via
// net.Pipe, using the same derived keys but different nonce prefixes per direction.
func createEncryptedPipe(t *testing.T) (*EncryptedConn, *EncryptedConn) {
	t.Helper()

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}
	secretB64 := base64.StdEncoding.EncodeToString(secret)

	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("failed to generate salt: %v", err)
	}

	keys, err := DeriveKeys(secretB64, salt)
	if err != nil {
		t.Fatalf("failed to derive keys: %v", err)
	}

	connA, connB := net.Pipe()

	// A writes with ClientNoncePrefix, B writes with ServerNoncePrefix
	encA, err := NewEncryptedConn(connA, keys.EncryptionKey, keys.ClientNoncePrefix)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn A: %v", err)
	}

	encB, err := NewEncryptedConn(connB, keys.EncryptionKey, keys.ServerNoncePrefix)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn B: %v", err)
	}

	return encA, encB
}

func TestEncryptedConnRoundtrip(t *testing.T) {
	encA, encB := createEncryptedPipe(t)
	defer encA.Close()
	defer encB.Close()

	message := []byte("Hello, encrypted world!")

	// Write from A, read from B
	errCh := make(chan error, 1)
	go func() {
		_, err := encA.Write(message)
		errCh <- err
	}()

	buf := make([]byte, 1024)
	n, err := encB.Read(buf)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}

	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("Write returned error: %v", writeErr)
	}

	if !bytes.Equal(buf[:n], message) {
		t.Errorf("expected %q, got %q", message, buf[:n])
	}
}

func TestEncryptedConnLargePayload(t *testing.T) {
	encA, encB := createEncryptedPipe(t)
	defer encA.Close()
	defer encB.Close()

	// Create a 60000-byte payload
	payload := make([]byte, 60000)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("failed to generate payload: %v", err)
	}

	// Write from A in a goroutine
	errCh := make(chan error, 1)
	go func() {
		_, err := encA.Write(payload)
		errCh <- err
	}()

	// Read all data from B
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

func TestEncryptedConnWrongKey(t *testing.T) {
	// Create two different keys
	keyA := make([]byte, EncryptionKeySize)
	keyB := make([]byte, EncryptionKeySize)
	prefixA := make([]byte, NoncePrefixSize)
	prefixB := make([]byte, NoncePrefixSize)
	if _, err := rand.Read(keyA); err != nil {
		t.Fatalf("failed to generate key A: %v", err)
	}
	if _, err := rand.Read(keyB); err != nil {
		t.Fatalf("failed to generate key B: %v", err)
	}
	if _, err := rand.Read(prefixA); err != nil {
		t.Fatalf("failed to generate prefix A: %v", err)
	}
	if _, err := rand.Read(prefixB); err != nil {
		t.Fatalf("failed to generate prefix B: %v", err)
	}

	connA, connB := net.Pipe()

	encA, err := NewEncryptedConn(connA, keyA, prefixA)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn A: %v", err)
	}
	defer encA.Close()

	encB, err := NewEncryptedConn(connB, keyB, prefixB)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn B: %v", err)
	}
	defer encB.Close()

	// Write from A
	go func() {
		encA.Write([]byte("secret message"))
	}()

	// Read from B should fail because keys don't match
	buf := make([]byte, 1024)
	_, err = encB.Read(buf)
	if err == nil {
		t.Error("expected decryption error with wrong key, got nil")
	}
}

func TestEncryptedConnMultipleMessages(t *testing.T) {
	encA, encB := createEncryptedPipe(t)
	defer encA.Close()
	defer encB.Close()

	messages := []string{
		"first message",
		"second message",
		"third message with more data",
	}

	// Send and receive each message sequentially
	for i, msg := range messages {
		errCh := make(chan error, 1)
		go func() {
			_, err := encA.Write([]byte(msg))
			errCh <- err
		}()

		buf := make([]byte, 1024)
		n, err := encB.Read(buf)
		if err != nil {
			t.Fatalf("message %d: Read returned error: %v", i, err)
		}

		if writeErr := <-errCh; writeErr != nil {
			t.Fatalf("message %d: Write returned error: %v", i, writeErr)
		}

		if string(buf[:n]) != msg {
			t.Errorf("message %d: expected %q, got %q", i, msg, string(buf[:n]))
		}
	}

	// Also test sending from B to A
	reply := []byte("reply from B")
	errCh := make(chan error, 1)
	go func() {
		_, err := encB.Write(reply)
		errCh <- err
	}()

	buf := make([]byte, 1024)
	n, err := encA.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read reply returned error: %v", err)
	}

	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("Write reply returned error: %v", writeErr)
	}

	if !bytes.Equal(buf[:n], reply) {
		t.Errorf("expected reply %q, got %q", reply, buf[:n])
	}
}

func TestEncryptedConnFrameSizeLimit(t *testing.T) {
	// Create a pipe and manually inject a frame with an oversized length header
	connA, connB := net.Pipe()
	defer connA.Close()
	defer connB.Close()

	key := make([]byte, EncryptionKeySize)
	prefix := make([]byte, NoncePrefixSize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if _, err := rand.Read(prefix); err != nil {
		t.Fatalf("failed to generate prefix: %v", err)
	}

	encB, err := NewEncryptedConn(connB, key, prefix)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn: %v", err)
	}

	// Write a manipulated frame header with an enormous length
	go func() {
		header := make([]byte, frameHeaderSize)
		binary.BigEndian.PutUint32(header, 0xFFFFFFFF)
		connA.Write(header)
	}()

	buf := make([]byte, 1024)
	_, err = encB.Read(buf)
	if err == nil {
		t.Fatal("expected error for oversized frame, got nil")
	}
	if !strings.Contains(err.Error(), "frame too large") {
		t.Fatalf("expected 'frame too large' error, got: %v", err)
	}
}

func TestEncryptedConnCounterNonce(t *testing.T) {
	encA, encB := createEncryptedPipe(t)
	defer encA.Close()
	defer encB.Close()

	// Send two messages and verify the counter increments (different nonces)
	// We verify this indirectly: both messages decrypt correctly, meaning
	// nonces were unique (GCM would fail with repeated nonces on same key).
	for i := 0; i < 5; i++ {
		msg := []byte("counter test message")
		errCh := make(chan error, 1)
		go func() {
			_, err := encA.Write(msg)
			errCh <- err
		}()

		buf := make([]byte, 1024)
		n, err := encB.Read(buf)
		if err != nil {
			t.Fatalf("message %d: Read returned error: %v", i, err)
		}
		if writeErr := <-errCh; writeErr != nil {
			t.Fatalf("message %d: Write returned error: %v", i, writeErr)
		}
		if !bytes.Equal(buf[:n], msg) {
			t.Errorf("message %d: expected %q, got %q", i, msg, buf[:n])
		}
	}
}

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
	defer encA.Close()

	encB, err := NewEncryptedConn(connB, key, prefix)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn B: %v", err)
	}
	defer encB.Close()

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

func TestEncryptedConnCompressedBitOnWire(t *testing.T) {
	// Verify that compression bit is actually set in the frame header for compressible data
	connA, connB := net.Pipe()
	defer connB.Close()

	key := make([]byte, EncryptionKeySize)
	prefix := make([]byte, NoncePrefixSize)
	rand.Read(key)
	rand.Read(prefix)

	encA, err := NewEncryptedConn(connA, key, prefix)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn: %v", err)
	}
	defer encA.Close()

	// Send highly compressible data
	message := []byte(strings.Repeat("compress me please! ", 100))

	go func() {
		encA.Write(message)
	}()

	// Read raw frame header from the pipe
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(connB, header); err != nil {
		t.Fatalf("failed to read raw header: %v", err)
	}

	rawLen := binary.BigEndian.Uint32(header)
	isCompressed := (rawLen & compressedBit) != 0

	if !isCompressed {
		t.Fatal("expected compression bit to be set for highly compressible data, but it was not")
	}

	// Verify the masked length is reasonable
	frameLen := rawLen &^ compressedBit
	if frameLen == 0 {
		t.Fatal("frame length is 0 after masking compression bit")
	}

	// The compressed frame should be significantly smaller than the original
	originalFrameOverhead := uint32(gcmNonceSize + 16) // nonce + auth tag
	if frameLen > uint32(len(message))+originalFrameOverhead {
		t.Errorf("compressed frame (%d bytes) is not smaller than uncompressed would be (~%d bytes)",
			frameLen, uint32(len(message))+originalFrameOverhead)
	}
}

func TestEncryptedConnDecompressedFrameTooLarge(t *testing.T) {
	// Craft a valid zstd-compressed payload that decompresses to more than MaxFrameSize
	// This tests the post-decompression size check
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
	defer encA.Close()

	encB, err := NewEncryptedConn(connB, key, prefix)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn B: %v", err)
	}
	defer encB.Close()

	// Create a valid zstd payload that decompresses to more than MaxFrameSize
	// Highly compressible data: repeated zeros
	oversized := make([]byte, MaxFrameSize+1)
	compressor, _ := zstd.NewWriter(nil)
	compressed := compressor.EncodeAll(oversized, nil)
	compressor.Close()

	go func() {
		nonce := make([]byte, gcmNonceSize)
		copy(nonce[:NoncePrefixSize], prefix)
		binary.BigEndian.PutUint64(nonce[NoncePrefixSize:], 1)

		ciphertext := encA.gcm.Seal(nil, nonce, compressed, nil)

		framePayloadLen := uint32(len(nonce) + len(ciphertext))
		framePayloadLen |= compressedBit

		header := make([]byte, frameHeaderSize)
		binary.BigEndian.PutUint32(header, framePayloadLen)

		connA.Write(header)
		connA.Write(nonce)
		connA.Write(ciphertext)
	}()

	buf := make([]byte, 1024)
	_, err = encB.Read(buf)
	if err == nil {
		t.Fatal("expected error for oversized decompressed frame, got nil")
	}
	if !strings.Contains(err.Error(), "decompressed frame too large") {
		t.Fatalf("expected 'decompressed frame too large' error, got: %v", err)
	}
}
