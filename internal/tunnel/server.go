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
	"time"

	"github.com/hashicorp/yamux"
	"github.com/mkloubert/go-proxy/internal/crypto"
	"github.com/mkloubert/go-proxy/internal/security"
)

const (
	handshakeTimeout        = 10 * time.Second
	streamHeaderTimeout     = 10 * time.Second
	yamuxAcceptBacklog      = 128
	yamuxStreamCloseTimeout = 60 * time.Second
	yamuxStreamOpenTimeout  = 30 * time.Second
	yamuxMaxStreamWindow    = 512 * 1024 // 512KB per stream
)

// Server is the remote side of the tunnel. It accepts incoming connections,
// performs an encrypted handshake, and multiplexes streams via yamux.
// Each stream carries a target address header followed by raw TCP data
// that is relayed to the destination.
type Server struct {
	secret      string
	connLimiter *security.ConnLimiter
	rateLimiter *security.RateLimiter
	ipFilter    *security.IPFilter

	// AllowPrivateIPs disables SSRF protection. Only set in tests.
	AllowPrivateIPs bool
}

// NewServer creates a new tunnel Server with the given base64-encoded secret.
func NewServer(secret string) *Server {
	return &Server{
		secret:      secret,
		connLimiter: security.NewConnLimiter(256),
		rateLimiter: security.NewRateLimiter(10, 5, 5, 5*time.Minute),
	}
}

// Close stops background goroutines.
func (s *Server) Close() {
	s.rateLimiter.Stop()
}

// SetIPFilter assigns an IPFilter to the server. When set, incoming
// connections from blocked IPs are rejected before any further processing.
func (s *Server) SetIPFilter(f *security.IPFilter) {
	s.ipFilter = f
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

		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

		// IP filter check — known-malicious or geo-blocked IPs are rejected immediately
		if s.ipFilter != nil && s.ipFilter.IsBlocked(ip) {
			slog.Debug("connection blocked by IP filter", "ip", ip)
			conn.Close()
			continue
		}

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

// handleConn performs the encrypted handshake, creates a yamux session,
// and dispatches each multiplexed stream.
func (s *Server) handleConn(conn net.Conn, ip string) {
	defer conn.Close()
	defer s.connLimiter.Release()

	// Enforce handshake deadline so unauthenticated connections
	// (bots, scanners) cannot hold goroutines open indefinitely.
	conn.SetDeadline(time.Now().Add(handshakeTimeout))

	// The server never sends data before the client proves knowledge of
	// the shared secret. On failure, the connection is closed immediately
	// with zero bytes sent — the port appears dead to the remote party.
	encConn, err := crypto.ServerHandshake(conn, s.secret)
	if err != nil {
		s.rateLimiter.RecordFailure(ip)
		slog.Debug("handshake failed", "remote", conn.RemoteAddr().String(), "error", err)
		return
	}

	// Clear deadline after successful handshake
	conn.SetDeadline(time.Time{})

	slog.Info("handshake completed", "remote", conn.RemoteAddr().String())

	// Create yamux session with hardened config
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.AcceptBacklog = yamuxAcceptBacklog
	yamuxCfg.StreamCloseTimeout = yamuxStreamCloseTimeout
	yamuxCfg.StreamOpenTimeout = yamuxStreamOpenTimeout
	yamuxCfg.MaxStreamWindowSize = yamuxMaxStreamWindow
	yamuxCfg.LogOutput = io.Discard

	session, err := yamux.Server(encConn, yamuxCfg)
	if err != nil {
		slog.Error("yamux session creation failed", "remote", conn.RemoteAddr().String(), "error", err)
		return
	}
	defer session.Close()

	// Accept streams
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

	// Deadline for reading the target address header
	stream.SetDeadline(time.Now().Add(streamHeaderTimeout))

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

	// Clear deadline for relay phase
	stream.SetDeadline(time.Time{})

	// Step 3: Dial the target (with SSRF protection unless disabled)
	var targetConn net.Conn
	var err error

	if s.AllowPrivateIPs {
		targetConn, err = net.Dial("tcp4", target)
	} else {
		targetConn, err = security.SafeDial(target)
	}

	if err != nil {
		slog.Debug("failed to dial target", "target", target, "error", err)
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
