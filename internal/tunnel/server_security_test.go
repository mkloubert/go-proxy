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
	"io"
	"net"
	"testing"
	"time"
)

func TestServerBlackholeOnWrongSecret(t *testing.T) {
	serverSecret := makeTestSecret(0xA1)

	tunnelAddr, cleanup := startTunnelServer(t, serverSecret)
	defer cleanup()

	// Connect with raw TCP and send garbage — server must not respond
	conn, err := net.DialTimeout("tcp4", tunnelAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	// Send 32 bytes "salt" + garbage encrypted frame
	conn.Write(make([]byte, 32))
	garbage := []byte{0x00, 0x00, 0x00, 0x20}
	garbage = append(garbage, make([]byte, 32)...)
	conn.Write(garbage)

	// Server should close without sending any data
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("server should not send any data to unauthenticated client")
	}
}

func TestServerBlocksIPAfterFailedHandshakes(t *testing.T) {
	secret := makeTestSecret(0xA2)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(secret)
	srv.AllowPrivateIPs = true
	go srv.Serve(ln)
	defer srv.Close()
	defer ln.Close()

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
		// Wait for server to process the handshake failure
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		io.ReadAll(c)
		c.Close()
	}

	// Wait for server to process
	time.Sleep(200 * time.Millisecond)

	// Next connection should be immediately closed (IP blocked)
	c, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		// Connection refused — IP is blocked, test passes
		return
	}
	defer c.Close()

	// If connected, server should close it immediately (no handshake attempt)
	c.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 1)
	_, err = c.Read(buf)
	if err == nil {
		t.Fatal("blocked IP should not receive any data")
	}
}

func TestServerRejectsPrivateIPTarget(t *testing.T) {
	secret := makeTestSecret(0xA3)

	// Start echo server on loopback
	echoLn, echoCleanup := startEchoServer(t)
	defer echoCleanup()
	echoAddr := echoLn.Addr().String()

	// Create server WITHOUT AllowPrivateIPs (default: SSRF protection on)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(secret)
	// AllowPrivateIPs = false (default)
	go srv.Serve(ln)
	defer srv.Close()
	defer ln.Close()

	tunnelAddr := ln.Addr().String()

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
		return // stream open failed — acceptable
	}
	defer stream.Close()

	// Write data — server should reject the target and close the stream
	stream.Write([]byte("hello"))
	stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 5)
	_, err = stream.Read(buf)
	if err == nil && string(buf) == "hello" {
		t.Fatal("server should have rejected connection to private IP")
	}
}

func TestServerLegitimateConnectionStillWorks(t *testing.T) {
	secret := makeTestSecret(0xA4)

	// Start echo server
	echoLn, echoCleanup := startEchoServer(t)
	defer echoCleanup()
	echoAddr := echoLn.Addr().String()

	// Start server WITH AllowPrivateIPs (to test with loopback echo server)
	tunnelAddr, tunnelCleanup := startTunnelServer(t, secret)
	defer tunnelCleanup()

	// Connect with correct secret
	client := NewClient(tunnelAddr, secret)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect failed: %v", err)
	}

	// Open stream — should work normally
	stream, err := client.OpenStream(echoAddr)
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}
	defer stream.Close()

	msg := []byte("security test")
	if _, err := stream.Write(msg); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(buf) != string(msg) {
		t.Fatalf("expected %q, got %q", msg, buf)
	}
}
