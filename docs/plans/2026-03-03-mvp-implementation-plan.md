# go-proxy MVP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a CLI tool that provides a local HTTP/HTTPS/SOCKS5 proxy tunneled through an AES-256-GCM encrypted connection to a remote server, preventing MITM attacks in untrusted networks.

**Architecture:** Single TCP connection between local and remote, encrypted with AES-256-GCM (length-prefixed framing), multiplexed with yamux. Local side auto-detects HTTP/HTTPS/SOCKS5 via first-byte peek. Remote side dials the actual internet targets.

**Tech Stack:** Go 1.25+, Cobra CLI, hashicorp/yamux, things-go/go-socks5, crypto/aes+cipher (stdlib), crypto/hkdf (stdlib), log/slog (stdlib)

**License Header (required on every .go file):**
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

## Task 1: Project Scaffolding and CLI Setup

**Files:**
- Create: `main.go`
- Create: `cmd/root.go`
- Create: `cmd/local.go`
- Create: `cmd/remote.go`

**Step 1: Create `main.go` entrypoint**

```go
// [LICENSE HEADER]

package main

import "github.com/mkloubert/go-proxy/cmd"

func main() {
	cmd.Execute()
}
```

**Step 2: Create `cmd/root.go` with root command and verbose flag**

```go
// [LICENSE HEADER]

package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var verbose bool

var rootCmd = &cobra.Command{
	Use:   "go-proxy",
	Short: "Encrypted tunnel proxy to prevent MITM attacks",
	Long:  "go-proxy provides a local HTTP/HTTPS/SOCKS5 proxy that tunnels all traffic through an AES-256-GCM encrypted connection to a trusted remote server.",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable debug logging")
	cobra.OnInitialize(initLogging)
}

func initLogging() {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}
```

**Step 3: Create `cmd/local.go` with stub local command**

```go
// [LICENSE HEADER]

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	localPort  int
	connectTo  string
)

var localCmd = &cobra.Command{
	Use:   "local",
	Short: "Start local proxy",
	Long:  "Start a local HTTP/HTTPS/SOCKS5 proxy that tunnels traffic to the remote server.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Starting local proxy on 127.0.0.1:%d, connecting to %s\n", localPort, connectTo)
		// TODO: implement
		return nil
	},
}

func init() {
	localCmd.Flags().IntVar(&localPort, "port", 8080, "local proxy listen port")
	localCmd.Flags().StringVar(&connectTo, "connect-to", "", "remote server address (host:port)")
	localCmd.MarkFlagRequired("connect-to")
	rootCmd.AddCommand(localCmd)
}
```

**Step 4: Create `cmd/remote.go` with stub remote command**

```go
// [LICENSE HEADER]

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var remotePort int

var remoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Start remote tunnel server",
	Long:  "Start the remote server that accepts encrypted tunnel connections and forwards traffic to the internet.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Starting remote server on :%d\n", remotePort)
		// TODO: implement
		return nil
	},
}

func init() {
	remoteCmd.Flags().IntVar(&remotePort, "port", 9876, "remote server listen port")
	rootCmd.AddCommand(remoteCmd)
}
```

**Step 5: Verify CLI compiles and runs**

Run: `go build -o go-proxy . && ./go-proxy --help && ./go-proxy local --help && ./go-proxy remote --help`
Expected: Help output for root, local, and remote commands.

---

## Task 2: Key Derivation (HKDF + AES-256-GCM)

**Files:**
- Create: `internal/crypto/keys.go`
- Create: `internal/crypto/keys_test.go`

**Step 1: Write the failing test for key derivation**

```go
// [LICENSE HEADER]

package crypto

import (
	"encoding/base64"
	"testing"
)

func TestDeriveKeys(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	secretB64 := base64.StdEncoding.EncodeToString(secret)

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 100)
	}

	keys, err := DeriveKeys(secretB64, salt)
	if err != nil {
		t.Fatalf("DeriveKeys failed: %v", err)
	}

	if len(keys.EncryptionKey) != 32 {
		t.Errorf("expected 32-byte encryption key, got %d", len(keys.EncryptionKey))
	}
	if len(keys.NoncePrefix) != 4 {
		t.Errorf("expected 4-byte nonce prefix, got %d", len(keys.NoncePrefix))
	}
}

func TestDeriveKeysDeterministic(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("test-secret-that-is-32-bytes-ok!"))
	salt := make([]byte, 32)

	keys1, _ := DeriveKeys(secret, salt)
	keys2, _ := DeriveKeys(secret, salt)

	for i := range keys1.EncryptionKey {
		if keys1.EncryptionKey[i] != keys2.EncryptionKey[i] {
			t.Fatal("same inputs must produce same keys")
		}
	}
}

func TestDeriveKeysInvalidBase64(t *testing.T) {
	_, err := DeriveKeys("not-valid-base64!!!", make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDeriveKeysDifferentSaltProducesDifferentKeys(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("test-secret-that-is-32-bytes-ok!"))
	salt1 := make([]byte, 32)
	salt2 := make([]byte, 32)
	salt2[0] = 1

	keys1, _ := DeriveKeys(secret, salt1)
	keys2, _ := DeriveKeys(secret, salt2)

	same := true
	for i := range keys1.EncryptionKey {
		if keys1.EncryptionKey[i] != keys2.EncryptionKey[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different salt must produce different keys")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/crypto/ -v -run TestDeriveKeys`
Expected: FAIL (package/functions don't exist yet)

**Step 3: Implement key derivation**

```go
// [LICENSE HEADER]

package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const (
	EncryptionKeySize = 32
	NoncePrefixSize   = 4
	SaltSize          = 32
)

type DerivedKeys struct {
	EncryptionKey []byte
	NoncePrefix   []byte
}

func DeriveKeys(secretBase64 string, salt []byte) (*DerivedKeys, error) {
	secret, err := base64.StdEncoding.DecodeString(secretBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 secret: %w", err)
	}

	encKey, err := hkdf.Key(sha256.New, secret, salt, "go-proxy-encryption-key", EncryptionKeySize)
	if err != nil {
		return nil, fmt.Errorf("HKDF encryption key derivation failed: %w", err)
	}

	noncePrefix, err := hkdf.Key(sha256.New, secret, salt, "go-proxy-nonce-prefix", NoncePrefixSize)
	if err != nil {
		return nil, fmt.Errorf("HKDF nonce prefix derivation failed: %w", err)
	}

	return &DerivedKeys{
		EncryptionKey: encKey,
		NoncePrefix:   noncePrefix,
	}, nil
}

func LoadSecret() (string, error) {
	secret := ""
	// Check standard env var
	for _, key := range []string{"GOPROXY_TUNNEL_SECRET"} {
		if v := lookupEnv(key); v != "" {
			secret = v
			break
		}
	}
	if secret == "" {
		return "", fmt.Errorf("GOPROXY_TUNNEL_SECRET environment variable not set")
	}
	// Validate it's valid base64
	if _, err := base64.StdEncoding.DecodeString(secret); err != nil {
		return "", fmt.Errorf("GOPROXY_TUNNEL_SECRET is not valid base64: %w", err)
	}
	return secret, nil
}

// lookupEnv is extracted for testability
var lookupEnv = osLookupEnv

func osLookupEnv(key string) string {
	// import "os" at package level
	return ""
}
```

Note: The `osLookupEnv` function needs to actually call `os.Getenv`. The implementation above is a skeleton -- the real implementation must import `os` and call `os.Getenv(key)`.

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/crypto/ -v -run TestDeriveKeys`
Expected: All PASS

---

## Task 3: AES-256-GCM Encrypted Connection Wrapper

**Files:**
- Create: `internal/crypto/tunnel.go`
- Create: `internal/crypto/tunnel_test.go`

**Step 1: Write failing tests for encrypted conn**

```go
// [LICENSE HEADER]

package crypto

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestEncryptedConnRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	noncePrefix := []byte{0x01, 0x02, 0x03, 0x04}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	encClient := NewEncryptedConn(client, key, noncePrefix)
	encServer := NewEncryptedConn(server, key, noncePrefix)

	msg := []byte("hello encrypted world")

	go func() {
		encClient.Write(msg)
	}()

	buf := make([]byte, 256)
	n, err := encServer.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("expected %q, got %q", msg, buf[:n])
	}
}

func TestEncryptedConnLargePayload(t *testing.T) {
	key := make([]byte, 32)
	noncePrefix := []byte{0x01, 0x02, 0x03, 0x04}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	encClient := NewEncryptedConn(client, key, noncePrefix)
	encServer := NewEncryptedConn(server, key, noncePrefix)

	msg := make([]byte, 60000)
	for i := range msg {
		msg[i] = byte(i % 256)
	}

	go func() {
		encClient.Write(msg)
	}()

	result, err := io.ReadAll(io.LimitReader(encServer, int64(len(msg))))
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if !bytes.Equal(result, msg) {
		t.Fatal("large payload mismatch")
	}
}

func TestEncryptedConnWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 0xFF
	noncePrefix := []byte{0x01, 0x02, 0x03, 0x04}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	encClient := NewEncryptedConn(client, key1, noncePrefix)
	encServer := NewEncryptedConn(server, key2, noncePrefix)

	go func() {
		encClient.Write([]byte("secret"))
		client.Close()
	}()

	buf := make([]byte, 256)
	_, err := encServer.Read(buf)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/crypto/ -v -run TestEncryptedConn`
Expected: FAIL

**Step 3: Implement EncryptedConn**

The `EncryptedConn` wraps a `net.Conn` and implements the `net.Conn` interface. It uses AES-256-GCM with length-prefixed framing:

```go
// [LICENSE HEADER]

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

const MaxFrameSize = 65536

type EncryptedConn struct {
	conn        net.Conn
	aead        cipher.AEAD
	noncePrefix []byte

	writeMu    sync.Mutex
	writeCount uint64

	readBuf []byte // buffered decrypted data from partial reads
}

func NewEncryptedConn(conn net.Conn, key, noncePrefix []byte) *EncryptedConn {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("aes.NewCipher: %v", err))
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("cipher.NewGCM: %v", err))
	}
	return &EncryptedConn{
		conn:        conn,
		aead:        aead,
		noncePrefix: noncePrefix,
	}
}

func (c *EncryptedConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxFrameSize {
			chunk = p[:MaxFrameSize]
		}

		nonce := make([]byte, c.aead.NonceSize())
		copy(nonce, c.noncePrefix)
		if _, err := rand.Read(nonce[len(c.noncePrefix):]); err != nil {
			return total, fmt.Errorf("nonce generation failed: %w", err)
		}

		ciphertext := c.aead.Seal(nil, nonce, chunk, nil)

		// Frame: [4-byte length][12-byte nonce][ciphertext]
		frameLen := uint32(len(nonce) + len(ciphertext))
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, frameLen)

		if _, err := c.conn.Write(header); err != nil {
			return total, err
		}
		if _, err := c.conn.Write(nonce); err != nil {
			return total, err
		}
		if _, err := c.conn.Write(ciphertext); err != nil {
			return total, err
		}

		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *EncryptedConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Read frame header (4 bytes)
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return 0, err
	}
	frameLen := binary.BigEndian.Uint32(header)

	// Read nonce + ciphertext
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(c.conn, frame); err != nil {
		return 0, err
	}

	nonceSize := c.aead.NonceSize()
	if int(frameLen) < nonceSize {
		return 0, fmt.Errorf("frame too small")
	}

	nonce := frame[:nonceSize]
	ciphertext := frame[nonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("decryption failed: %w", err)
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		c.readBuf = plaintext[n:]
	}
	return n, nil
}

// Delegate remaining net.Conn methods to underlying conn
func (c *EncryptedConn) Close() error                     { return c.conn.Close() }
func (c *EncryptedConn) LocalAddr() net.Addr               { return c.conn.LocalAddr() }
func (c *EncryptedConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *EncryptedConn) SetDeadline(t interface{}) error     { return nil }
func (c *EncryptedConn) SetReadDeadline(t interface{}) error { return nil }
func (c *EncryptedConn) SetWriteDeadline(t interface{}) error { return nil }
```

Note: The `SetDeadline` methods need proper `time.Time` parameters. The code above is a skeleton -- the actual implementation must use `time.Time`.

**Step 4: Run tests**

Run: `go test ./internal/crypto/ -v -run TestEncryptedConn`
Expected: All PASS

---

## Task 4: Handshake Protocol

**Files:**
- Create: `internal/crypto/handshake.go`
- Create: `internal/crypto/handshake_test.go`

**Step 1: Write failing tests for handshake**

Test that client and server can perform a salt exchange and derive identical keys, and that a challenge/response verifies the shared secret.

```go
// [LICENSE HEADER]

package crypto

import (
	"encoding/base64"
	"net"
	"testing"
)

func TestHandshakeSuccess(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("my-32-byte-secret-key-for-tests!"))

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var clientConn, serverConn net.Conn
	var clientErr, serverErr error

	go func() {
		clientConn, clientErr = ClientHandshake(client, secret)
	}()
	serverConn, serverErr = ServerHandshake(server, secret)

	if clientErr != nil {
		t.Fatalf("client handshake failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake failed: %v", serverErr)
	}
	if clientConn == nil || serverConn == nil {
		t.Fatal("expected non-nil connections")
	}
}

func TestHandshakeWrongSecret(t *testing.T) {
	secret1 := base64.StdEncoding.EncodeToString([]byte("my-32-byte-secret-key-for-tests!"))
	secret2 := base64.StdEncoding.EncodeToString([]byte("different-secret-key-32-bytes-xx"))

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var clientErr, serverErr error

	go func() {
		_, clientErr = ClientHandshake(client, secret1)
	}()
	_, serverErr = ServerHandshake(server, secret2)

	if clientErr == nil && serverErr == nil {
		t.Fatal("expected at least one side to fail with wrong secret")
	}
}
```

**Step 2: Run to verify failure**

Run: `go test ./internal/crypto/ -v -run TestHandshake`
Expected: FAIL

**Step 3: Implement handshake**

```go
// [LICENSE HEADER]

package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
)

const challengeSize = 32

func ClientHandshake(conn net.Conn, secretBase64 string) (net.Conn, error) {
	// 1. Generate and send salt
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}
	if _, err := conn.Write(salt); err != nil {
		return nil, fmt.Errorf("sending salt: %w", err)
	}

	// 2. Derive keys
	keys, err := DeriveKeys(secretBase64, salt)
	if err != nil {
		return nil, fmt.Errorf("deriving keys: %w", err)
	}

	// 3. Create encrypted conn
	encConn := NewEncryptedConn(conn, keys.EncryptionKey, keys.NoncePrefix)

	// 4. Read challenge from server
	challenge := make([]byte, challengeSize)
	if _, err := io.ReadFull(encConn, challenge); err != nil {
		return nil, fmt.Errorf("reading challenge: %w", err)
	}

	// 5. Send challenge back (echo)
	if _, err := encConn.Write(challenge); err != nil {
		return nil, fmt.Errorf("sending challenge response: %w", err)
	}

	return encConn, nil
}

func ServerHandshake(conn net.Conn, secretBase64 string) (net.Conn, error) {
	// 1. Read salt from client
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return nil, fmt.Errorf("reading salt: %w", err)
	}

	// 2. Derive keys
	keys, err := DeriveKeys(secretBase64, salt)
	if err != nil {
		return nil, fmt.Errorf("deriving keys: %w", err)
	}

	// 3. Create encrypted conn
	encConn := NewEncryptedConn(conn, keys.EncryptionKey, keys.NoncePrefix)

	// 4. Generate and send challenge
	challenge := make([]byte, challengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generating challenge: %w", err)
	}
	if _, err := encConn.Write(challenge); err != nil {
		return nil, fmt.Errorf("sending challenge: %w", err)
	}

	// 5. Read response and verify
	response := make([]byte, challengeSize)
	if _, err := io.ReadFull(encConn, response); err != nil {
		return nil, fmt.Errorf("reading challenge response: %w", err)
	}
	if subtle.ConstantTimeCompare(challenge, response) != 1 {
		return nil, fmt.Errorf("challenge verification failed: secrets do not match")
	}

	return encConn, nil
}
```

**Step 4: Run tests**

Run: `go test ./internal/crypto/ -v -run TestHandshake`
Expected: All PASS

---

## Task 5: Install Dependencies (yamux, go-socks5)

**Step 1: Add yamux and go-socks5 to go.mod**

Run: `go get github.com/hashicorp/yamux@latest && go get github.com/things-go/go-socks5@latest`

**Step 2: Verify go.mod updated**

Run: `cat go.mod`
Expected: Both dependencies listed in require block.

---

## Task 6: Tunnel Server (Remote Side)

**Files:**
- Create: `internal/tunnel/server.go`
- Create: `internal/tunnel/server_test.go`

**Step 1: Write failing test for tunnel server**

Test that the server accepts a connection, performs handshake, creates yamux session, and handles streams (reads target address, dials target, relays data).

```go
// [LICENSE HEADER]

package tunnel

import (
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/mkloubert/go-proxy/internal/crypto"
)

func TestServerAcceptsAndRelays(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("my-32-byte-secret-key-for-tests!"))

	// Start a simple echo server as the "internet target"
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		conn, _ := echoLn.Accept()
		if conn != nil {
			io.Copy(conn, conn)
			conn.Close()
		}
	}()

	// Start tunnel server
	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverLn.Close()

	srv := NewServer(secret)
	go srv.Serve(serverLn)

	// Connect as client
	conn, err := net.Dial("tcp", serverLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	encConn, err := crypto.ClientHandshake(conn, secret)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	// Create yamux client session
	// (full test needs yamux import -- see implementation)
	_ = encConn // placeholder
}
```

Note: Full test requires yamux. The actual test will create a yamux client session, open a stream, write target address, send data, and verify echo response.

**Step 2: Implement tunnel server**

```go
// [LICENSE HEADER]

package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/hashicorp/yamux"
	"github.com/mkloubert/go-proxy/internal/crypto"
)

type Server struct {
	secret string
}

func NewServer(secret string) *Server {
	return &Server{secret: secret}
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	encConn, err := crypto.ServerHandshake(conn, s.secret)
	if err != nil {
		slog.Error("handshake failed", "error", err, "remote", conn.RemoteAddr())
		return
	}
	slog.Info("tunnel established", "remote", conn.RemoteAddr())

	session, err := yamux.Server(encConn, nil)
	if err != nil {
		slog.Error("yamux session failed", "error", err)
		return
	}
	defer session.Close()

	for {
		stream, err := session.Accept()
		if err != nil {
			slog.Debug("session closed", "error", err)
			return
		}
		go s.handleStream(stream)
	}
}

func (s *Server) handleStream(stream net.Conn) {
	defer stream.Close()

	// Read target address: [2 bytes length][N bytes address]
	var addrLen uint16
	if err := binary.Read(stream, binary.BigEndian, &addrLen); err != nil {
		slog.Error("reading target address length", "error", err)
		return
	}
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		slog.Error("reading target address", "error", err)
		return
	}
	target := string(addrBuf)
	slog.Debug("connecting to target", "target", target)

	// Dial actual target
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		slog.Error("dial target failed", "target", target, "error", err)
		return
	}
	defer targetConn.Close()

	// Bidirectional relay
	relay(stream, targetConn)
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	<-done
}
```

**Step 3: Run tests**

Run: `go test ./internal/tunnel/ -v`
Expected: PASS

---

## Task 7: Tunnel Client (Local Side)

**Files:**
- Create: `internal/tunnel/client.go`
- Create: `internal/tunnel/client_test.go`

**Step 1: Implement tunnel client with reconnect logic**

```go
// [LICENSE HEADER]

package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/mkloubert/go-proxy/internal/crypto"
)

type Client struct {
	remoteAddr string
	secret     string

	mu      sync.RWMutex
	session *yamux.Session
}

func NewClient(remoteAddr, secret string) *Client {
	return &Client{
		remoteAddr: remoteAddr,
		secret:     secret,
	}
}

func (c *Client) Connect(ctx context.Context) error {
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		err := c.connect()
		if err == nil {
			return nil
		}
		slog.Error("tunnel connect failed", "error", err, "retry_in", backoff)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *Client) connect() error {
	conn, err := net.Dial("tcp", c.remoteAddr)
	if err != nil {
		return fmt.Errorf("dial remote: %w", err)
	}

	encConn, err := crypto.ClientHandshake(conn, c.secret)
	if err != nil {
		conn.Close()
		return fmt.Errorf("handshake: %w", err)
	}

	session, err := yamux.Client(encConn, nil)
	if err != nil {
		conn.Close()
		return fmt.Errorf("yamux client: %w", err)
	}

	c.mu.Lock()
	if c.session != nil {
		c.session.Close()
	}
	c.session = session
	c.mu.Unlock()

	slog.Info("tunnel connected", "remote", c.remoteAddr)
	return nil
}

func (c *Client) OpenStream(target string) (net.Conn, error) {
	c.mu.RLock()
	session := c.session
	c.mu.RUnlock()

	if session == nil {
		return nil, fmt.Errorf("tunnel not connected")
	}

	stream, err := session.Open()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	// Write target address: [2 bytes length][N bytes address]
	addrBytes := []byte(target)
	if err := binary.Write(stream, binary.BigEndian, uint16(len(addrBytes))); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write target length: %w", err)
	}
	if _, err := stream.Write(addrBytes); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write target address: %w", err)
	}

	return stream, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		return c.session.Close()
	}
	return nil
}
```

**Step 2: Write test verifying client can open a stream through the tunnel**

Full integration test: start echo server, start tunnel server, connect tunnel client, open stream to echo server, verify data round-trips.

**Step 3: Run tests**

Run: `go test ./internal/tunnel/ -v`
Expected: PASS

---

## Task 8: HTTP/HTTPS Proxy Handler

**Files:**
- Create: `internal/proxy/http.go`
- Create: `internal/proxy/http_test.go`

**Step 1: Implement HTTP proxy that handles both plain HTTP and CONNECT**

```go
// [LICENSE HEADER]

package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
)

type DialFunc func(target string) (net.Conn, error)

type HTTPProxy struct {
	dial DialFunc
}

func NewHTTPProxy(dial DialFunc) *HTTPProxy {
	return &HTTPProxy{dial: dial}
}

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *HTTPProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	slog.Debug("CONNECT", "target", r.Host)

	targetConn, err := p.dial(r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		slog.Error("hijack failed", "error", err)
		return
	}
	defer clientConn.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(targetConn, clientConn); done <- struct{}{} }()
	go func() { io.Copy(clientConn, targetConn); done <- struct{}{} }()
	<-done
}

func (p *HTTPProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		http.Error(w, "missing host in request", http.StatusBadRequest)
		return
	}

	target := r.URL.Host
	if r.URL.Port() == "" {
		target = fmt.Sprintf("%s:80", target)
	}
	slog.Debug("HTTP", "method", r.Method, "target", target)

	targetConn, err := p.dial(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Write the original request to the target
	r.RequestURI = ""
	if err := r.Write(targetConn); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Read the response and relay back
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		slog.Error("hijack failed", "error", err)
		return
	}
	defer clientConn.Close()

	// Relay response back to client
	go io.Copy(buf, targetConn)
	io.Copy(targetConn, buf)
}
```

**Step 2: Run tests**

Run: `go test ./internal/proxy/ -v`
Expected: PASS

---

## Task 9: SOCKS5 Proxy Handler

**Files:**
- Create: `internal/proxy/socks5.go`

**Step 1: Implement SOCKS5 proxy with custom dial through tunnel**

```go
// [LICENSE HEADER]

package proxy

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/things-go/go-socks5"
)

func NewSOCKS5Server(dial DialFunc) *socks5.Server {
	return socks5.NewServer(
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dial(addr)
		}),
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stderr, "socks5: ", log.LstdFlags))),
	)
}
```

---

## Task 10: Protocol Detection and Unified Listener

**Files:**
- Create: `internal/proxy/handler.go`
- Create: `internal/proxy/handler_test.go`

**Step 1: Implement protocol detection via first-byte peek**

```go
// [LICENSE HEADER]

package proxy

import (
	"bufio"
	"log/slog"
	"net"
	"net/http"
)

type ProxyHandler struct {
	httpProxy   *HTTPProxy
	socks5Srv   *socks5.Server
}

func NewProxyHandler(dial DialFunc) *ProxyHandler {
	return &ProxyHandler{
		httpProxy:  NewHTTPProxy(dial),
		socks5Srv:  NewSOCKS5Server(dial),
	}
}

func (h *ProxyHandler) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go h.handleConn(conn)
	}
}

func (h *ProxyHandler) handleConn(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		slog.Error("peek failed", "error", err)
		return
	}

	// Wrap conn so the peeked byte is not lost
	wrappedConn := &bufferedConn{Reader: br, Conn: conn}

	if first[0] == 0x05 {
		// SOCKS5
		slog.Debug("detected SOCKS5")
		h.socks5Srv.ServeConn(wrappedConn)
	} else {
		// HTTP/HTTPS
		slog.Debug("detected HTTP")
		// Use http.Server with single connection
		srv := &http.Server{Handler: h.httpProxy}
		srv.Serve(&singleConnListener{conn: wrappedConn})
	}
}

// bufferedConn wraps a net.Conn with a bufio.Reader so peeked bytes are available
type bufferedConn struct {
	*bufio.Reader
	net.Conn
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

// singleConnListener is a net.Listener that serves exactly one connection
type singleConnListener struct {
	conn net.Conn
	done bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, net.ErrClosed
	}
	l.done = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
```

**Step 2: Run tests**

Run: `go test ./internal/proxy/ -v`
Expected: PASS

---

## Task 11: Wire Everything Together in CLI Commands

**Files:**
- Modify: `cmd/local.go`
- Modify: `cmd/remote.go`

**Step 1: Implement `cmd/remote.go` RunE**

```go
RunE: func(cmd *cobra.Command, args []string) error {
	secret, err := crypto.LoadSecret()
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", remotePort))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	slog.Info("remote server started", "port", remotePort)

	// Graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	srv := tunnel.NewServer(secret)
	return srv.Serve(ln)
}
```

**Step 2: Implement `cmd/local.go` RunE**

```go
RunE: func(cmd *cobra.Command, args []string) error {
	secret, err := crypto.LoadSecret()
	if err != nil {
		return err
	}

	client := tunnel.NewClient(connectTo, secret)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return err
	}
	defer client.Close()

	dial := func(target string) (net.Conn, error) {
		return client.OpenStream(target)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	slog.Info("local proxy started", "port", localPort, "remote", connectTo)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	handler := proxy.NewProxyHandler(dial)
	return handler.Serve(ln)
}
```

**Step 3: Verify build**

Run: `go build -o go-proxy .`
Expected: Compiles without errors.

---

## Task 12: Integration Test (End-to-End)

**Files:**
- Create: `internal/integration_test.go`

**Step 1: Write an end-to-end test**

Start a simple HTTP server (the "internet"), start remote tunnel server, start local client, make HTTP request through the local proxy, verify the response arrives correctly.

This test exercises the full path: HTTP client -> local proxy -> encrypted tunnel -> remote server -> target HTTP server -> back.

**Step 2: Run integration test**

Run: `go test ./internal/ -v -run TestIntegration -timeout 30s`
Expected: PASS

---

## Task 13: LICENSE File and README

**Files:**
- Create: `LICENSE`
- Create: `README.md`

**Step 1: Create LICENSE file with MIT license text**

Use the license header from CLAUDE.md as the full LICENSE file.

**Step 2: Create README.md in simple English**

Include: what the tool does, how to build, how to use (with examples for local and remote commands), how to set the secret.

---

## Task 14: Update TASKS.md and MILESTONE.md

**Files:**
- Modify: `TASKS.md`
- Modify: `MILESTONE.md`

Per CLAUDE.md requirements, update TASKS.md with the checklist of completed tasks and mark the milestone as complete.

---
