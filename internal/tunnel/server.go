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
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/hashicorp/yamux"
	"github.com/mkloubert/go-proxy/internal/crypto"
)

// Server is the remote side of the tunnel. It accepts incoming connections,
// performs an encrypted handshake, and multiplexes streams via yamux.
// Each stream carries a target address header followed by raw TCP data
// that is relayed to the destination.
type Server struct {
	secret string
}

// NewServer creates a new tunnel Server with the given base64-encoded secret.
func NewServer(secret string) *Server {
	return &Server{
		secret: secret,
	}
}

// Serve accepts connections on the given listener and handles each one
// in a separate goroutine. It blocks until the listener is closed.
func (s *Server) Serve(ln net.Listener) error {
	slog.Info("tunnel server listening", "addr", ln.Addr().String())

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept failed: %w", err)
		}

		slog.Info("new tunnel connection", "remote", conn.RemoteAddr().String())
		go s.handleConn(conn)
	}
}

// handleConn performs the encrypted handshake, creates a yamux session,
// and dispatches each multiplexed stream.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	// Step 1: Encrypted handshake
	encConn, err := crypto.ServerHandshake(conn, s.secret)
	if err != nil {
		slog.Error("handshake failed", "remote", conn.RemoteAddr().String(), "error", err)
		return
	}

	slog.Info("handshake completed", "remote", conn.RemoteAddr().String())

	// Step 2: Create yamux session
	session, err := yamux.Server(encConn, nil)
	if err != nil {
		slog.Error("yamux session creation failed", "remote", conn.RemoteAddr().String(), "error", err)
		return
	}
	defer session.Close()

	// Step 3: Accept streams
	for {
		stream, err := session.Accept()
		if err != nil {
			if err != io.EOF {
				slog.Error("stream accept failed", "remote", conn.RemoteAddr().String(), "error", err)
			}
			return
		}

		slog.Debug("new stream accepted", "remote", conn.RemoteAddr().String())
		go s.handleStream(stream)
	}
}

// handleStream reads the target address from the stream, dials the target,
// and relays data bidirectionally.
func (s *Server) handleStream(stream net.Conn) {
	defer stream.Close()

	// Step 1: Read target address length (2 bytes big-endian)
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
	slog.Debug("dialing target", "target", target)

	// Step 3: Dial the target
	targetConn, err := net.Dial("tcp4", target)
	if err != nil {
		slog.Error("failed to dial target", "target", target, "error", err)
		return
	}
	defer targetConn.Close()

	slog.Debug("connected to target", "target", target)

	// Step 4: Bidirectional relay
	relay(stream, targetConn)
}

// relay copies data bidirectionally between two connections.
// It launches two goroutines and waits for the first one to complete,
// then closes both connections to unblock the other goroutine.
func relay(a, b net.Conn) {
	var once sync.Once
	done := make(chan struct{})

	closeAll := func() {
		a.Close()
		b.Close()
	}

	go func() {
		io.Copy(a, b)
		once.Do(closeAll)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(b, a)
		once.Do(closeAll)
		done <- struct{}{}
	}()

	// Wait for both goroutines to finish
	<-done
	<-done
}
