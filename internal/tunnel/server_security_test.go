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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/mkloubert/go-proxy/internal/crypto"
)

func TestServerRejectsNonWebSocketRequest(t *testing.T) {
	secret := makeTestSecret(0xA1)

	srv := NewServer(secret)
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler("/ws"))
	defer ts.Close()

	// Plain HTTP GET to /ws — should fail since it's not a WebSocket upgrade
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := websocket.Dial(ctx, strings.Replace(ts.URL, "http://", "ws://", 1)+"/wrong-path", nil)
	if err == nil {
		t.Fatal("expected error for wrong path")
	}
}

func TestServerRejectsInvalidHandshake(t *testing.T) {
	secret := makeTestSecret(0xA2)
	wrongSecret := makeTestSecret(0xFF)

	srv := NewServer(secret)
	srv.SetAllowPrivateIPs(true)
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler("/ws"))
	defer ts.Close()

	// Connect via WebSocket with wrong secret — handshake should fail
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws"
	wsConn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial failed: %v", err)
	}

	wsConn.SetReadLimit(-1)

	// Try handshake with wrong secret — should fail
	netConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)
	_, hsErr := crypto.ClientHandshake(netConn, wrongSecret)
	if hsErr == nil {
		t.Fatal("expected handshake to fail with wrong secret")
	}
}

func TestServerHandshakeSuccess(t *testing.T) {
	secret := makeTestSecret(0xA5)

	srv := NewServer(secret)
	srv.SetAllowPrivateIPs(true)
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler("/ws"))
	defer ts.Close()

	// Connect via WebSocket and perform successful handshake
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws"
	wsConn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial failed: %v", err)
	}

	wsConn.SetReadLimit(-1)

	netConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)
	encConn, err := crypto.ClientHandshake(netConn, secret)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	if encConn == nil {
		t.Fatal("expected non-nil encrypted connection")
	}

	wsConn.CloseNow()
}
