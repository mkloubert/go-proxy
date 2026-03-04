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
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mkloubert/go-proxy/internal/crypto"
	"github.com/mkloubert/go-proxy/internal/stego"
)

func TestServerRejectsGarbagePNG(t *testing.T) {
	secret := makeTestSecret(0xA1)

	srv := NewServer(secret)
	defer srv.Close()

	handler := srv.Handler()

	// Send garbage data (not valid PNG) — server must return 404
	garbage := make([]byte, 64)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/galleries/test-uuid/pictures", bytes.NewReader(garbage))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for garbage PNG, got %d", w.Code)
	}

	// Verify no sensitive info is leaked in the body
	body := w.Body.String()
	if body != "Not Found\n" {
		t.Fatalf("unexpected response body: %q", body)
	}
}

func TestServerRejectsInvalidHandshake(t *testing.T) {
	secret := makeTestSecret(0xA2)

	srv := NewServer(secret)
	defer srv.Close()

	handler := srv.Handler()

	// Create a valid PNG with garbage handshake data
	garbagePayload := make([]byte, 64)
	w2, h2 := stego.RequiredImageSize(len(garbagePayload))
	carrier := stego.GenerateCarrier(w2, h2)
	pngBytes, err := stego.Embed(carrier, garbagePayload)
	if err != nil {
		t.Fatalf("failed to embed: %v", err)
	}

	// No Authorization header = handshake attempt
	req := httptest.NewRequest(http.MethodPost, "/api/v1/galleries/test-uuid/pictures", bytes.NewReader(pngBytes))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should fail because handshake data is garbage
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for invalid handshake, got %d", w.Code)
	}
}

func TestServerRejectsInvalidToken(t *testing.T) {
	secret := makeTestSecret(0xA3)

	srv := NewServer(secret)
	defer srv.Close()

	handler := srv.Handler()

	// Create a valid PNG with some payload
	payload := []byte("test data")
	w2, h2 := stego.RequiredImageSize(len(payload))
	carrier := stego.GenerateCarrier(w2, h2)
	pngBytes, err := stego.Embed(carrier, payload)
	if err != nil {
		t.Fatalf("failed to embed: %v", err)
	}

	// Send with an invalid token
	req := httptest.NewRequest(http.MethodPost, "/api/v1/galleries/test-uuid/pictures", bytes.NewReader(pngBytes))
	req.Header.Set("Authorization", "Bearer invalid-token-that-does-not-exist")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for invalid token, got %d", w.Code)
	}
}

func TestServerEmptyBodyReturns404(t *testing.T) {
	secret := makeTestSecret(0xA4)

	srv := NewServer(secret)
	defer srv.Close()

	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/galleries/test-uuid/pictures", bytes.NewReader([]byte{}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for empty body, got %d", w.Code)
	}
}

func TestServerHandshakeSuccess(t *testing.T) {
	secret := makeTestSecret(0xA5)

	srv := NewServer(secret)
	srv.SetAllowPrivateIPs(true)
	defer srv.Close()

	handler := srv.Handler()

	// Create a proper handshake payload using the crypto package
	hsPayload, _, _, err := crypto.ClientHandshakePayload(secret)
	if err != nil {
		t.Fatalf("failed to create handshake payload: %v", err)
	}

	// Embed handshake payload in PNG
	w2, h2 := stego.RequiredImageSize(len(hsPayload))
	carrier := stego.GenerateCarrier(w2, h2)
	pngBytes, err := stego.Embed(carrier, hsPayload)
	if err != nil {
		t.Fatalf("failed to embed: %v", err)
	}

	// Send handshake (no Authorization header)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/galleries/test-uuid/pictures", bytes.NewReader(pngBytes))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		body, _ := io.ReadAll(w.Body)
		t.Fatalf("expected 201 for successful handshake, got %d: %s", w.Code, body)
	}

	// Response should contain Authorization header with token
	authHeader := w.Header().Get("Authorization")
	if authHeader == "" {
		t.Fatal("expected Authorization header in response")
	}
	if len(authHeader) < len("Bearer ")+8 {
		t.Fatalf("token too short: %s", authHeader)
	}

	// Response should be a PNG
	contentType := w.Header().Get("Content-Type")
	if contentType != "image/png" {
		t.Fatalf("expected Content-Type image/png, got %s", contentType)
	}

	// Should be able to extract data from the response PNG
	respData, err := stego.Extract(w.Body.Bytes())
	if err != nil {
		t.Fatalf("failed to extract from response PNG: %v", err)
	}
	if len(respData) == 0 {
		t.Fatal("expected non-empty handshake response data")
	}
}
