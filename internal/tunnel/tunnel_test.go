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

package tunnel

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// makeTestSecret generates a valid base64-encoded 32-byte secret for testing.
func makeTestSecret(seed byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// startEchoServer starts a TCP echo server that echoes all received data
// back to the sender. It returns the listener and a cleanup function.
func startEchoServer(t *testing.T) (net.Listener, func()) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}

	var wg sync.WaitGroup

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	cleanup := func() {
		ln.Close()
		wg.Wait()
	}

	return ln, cleanup
}

// startTunnelServer starts a tunnel server on a random port with the given
// secret. It returns the listener address and a cleanup function.
func startTunnelServer(t *testing.T, secret string) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start tunnel server listener: %v", err)
	}

	srv := NewServer(secret)

	go func() {
		srv.Serve(ln)
	}()

	cleanup := func() {
		ln.Close()
	}

	return ln.Addr().String(), cleanup
}

func TestTunnelRoundtrip(t *testing.T) {
	secret := makeTestSecret(0xAA)

	// Step 1: Start echo server (the "internet target")
	echoLn, echoCleanup := startEchoServer(t)
	defer echoCleanup()

	echoAddr := echoLn.Addr().String()

	// Step 2: Start tunnel server
	tunnelAddr, tunnelCleanup := startTunnelServer(t, secret)
	defer tunnelCleanup()

	// Step 3: Create tunnel client and connect
	client := NewClient(tunnelAddr, secret)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("client.Connect failed: %v", err)
	}

	// Step 4: Open stream to echo server
	stream, err := client.OpenStream(echoAddr)
	if err != nil {
		t.Fatalf("client.OpenStream failed: %v", err)
	}
	defer stream.Close()

	// Step 5: Write "hello" and read it back
	msg := []byte("hello")
	if _, err := stream.Write(msg); err != nil {
		t.Fatalf("stream.Write failed: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("stream.Read failed: %v", err)
	}

	// Step 6: Verify data matches
	if string(buf) != string(msg) {
		t.Fatalf("expected %q, got %q", msg, buf)
	}
}

func TestTunnelMultipleStreams(t *testing.T) {
	secret := makeTestSecret(0xBB)

	// Step 1: Start echo server
	echoLn, echoCleanup := startEchoServer(t)
	defer echoCleanup()

	echoAddr := echoLn.Addr().String()

	// Step 2: Start tunnel server
	tunnelAddr, tunnelCleanup := startTunnelServer(t, secret)
	defer tunnelCleanup()

	// Step 3: Create tunnel client and connect
	client := NewClient(tunnelAddr, secret)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("client.Connect failed: %v", err)
	}

	// Step 4: Open 3 streams simultaneously
	const numStreams = 3
	var wg sync.WaitGroup
	errs := make(chan error, numStreams)

	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			stream, err := client.OpenStream(echoAddr)
			if err != nil {
				errs <- fmt.Errorf("stream %d: OpenStream failed: %w", idx, err)
				return
			}
			defer stream.Close()

			// Write unique data per stream
			msg := []byte(fmt.Sprintf("stream-%d-data", idx))
			if _, err := stream.Write(msg); err != nil {
				errs <- fmt.Errorf("stream %d: Write failed: %w", idx, err)
				return
			}

			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(stream, buf); err != nil {
				errs <- fmt.Errorf("stream %d: Read failed: %w", idx, err)
				return
			}

			if string(buf) != string(msg) {
				errs <- fmt.Errorf("stream %d: expected %q, got %q", idx, msg, buf)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatal(err)
	}
}

func TestTunnelWrongSecret(t *testing.T) {
	serverSecret := makeTestSecret(0xCC)
	clientSecret := makeTestSecret(0xDD)

	// Step 1: Start tunnel server with secret A
	tunnelAddr, tunnelCleanup := startTunnelServer(t, serverSecret)
	defer tunnelCleanup()

	// Step 2: Create tunnel client with secret B
	client := NewClient(tunnelAddr, clientSecret)
	defer client.Close()

	// Step 3: Connect should fail (handshake error due to secret mismatch)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := client.Connect(ctx)

	// The connect should fail because the context times out after retries,
	// or the handshake itself fails.
	if err == nil {
		// If Connect succeeded, try to open a stream - it should fail
		// because the handshake would have produced garbage.
		stream, openErr := client.OpenStream("127.0.0.1:1")
		if openErr == nil {
			stream.Close()
			t.Fatal("expected error with wrong secret, but connection and stream succeeded")
		}
	}
	// If err != nil, the test passes: wrong secret caused failure.
}
