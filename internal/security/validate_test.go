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

package security

import (
	"net"
	"strings"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"::1", true},
		{"fe80::1", true},
		{"0.0.0.0", true},
		{"::", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		{"172.32.0.1", false},
		{"192.169.0.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP: %s", tt.ip)
		}
		got := IsPrivateIP(ip)
		if got != tt.private {
			t.Errorf("IsPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}

func TestIsPrivateIPNil(t *testing.T) {
	if !IsPrivateIP(nil) {
		t.Error("IsPrivateIP(nil) should return true")
	}
}

func TestValidateTarget(t *testing.T) {
	tests := []struct {
		addr    string
		wantErr bool
	}{
		// Valid public addresses
		{"8.8.8.8:443", false},
		{"1.1.1.1:80", false},
		{"93.184.216.34:8080", false},

		// Private IPs — must be rejected
		{"127.0.0.1:80", true},
		{"10.0.0.1:443", true},
		{"172.16.0.1:80", true},
		{"192.168.1.1:80", true},
		{"[::1]:80", true},
		{"0.0.0.0:80", true},

		// Invalid format
		{"noport", true},
		{"", true},
		{":80", true},

		// Invalid port
		{"8.8.8.8:0", true},
		{"8.8.8.8:99999", true},
		{"8.8.8.8:-1", true},
		{"8.8.8.8:abc", true},

		// Address too long
		{strings.Repeat("a", 250) + ".com:80", true},
	}

	for _, tt := range tests {
		err := ValidateTarget(tt.addr)
		if tt.wantErr && err == nil {
			t.Errorf("ValidateTarget(%q) = nil, want error", tt.addr)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("ValidateTarget(%q) = %v, want nil", tt.addr, err)
		}
	}
}

func TestSafeDialRejectsPrivateIP(t *testing.T) {
	_, err := SafeDial("127.0.0.1:80")
	if err == nil {
		t.Fatal("SafeDial should reject 127.0.0.1")
	}

	_, err = SafeDial("10.0.0.1:80")
	if err == nil {
		t.Fatal("SafeDial should reject 10.0.0.1")
	}
}
