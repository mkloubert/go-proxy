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
	"fmt"
	"net"
	"strconv"
	"time"
)

const (
	maxAddrLen  = 253
	dialTimeout = 30 * time.Second
)

// IsPrivateIP returns true if the IP is loopback, private, link-local,
// multicast, or unspecified. Returns true for nil.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// ValidateTarget checks that addr is a valid host:port with a public IP.
// It rejects private IPs, invalid formats, and addresses longer than 253 bytes.
func ValidateTarget(addr string) error {
	if len(addr) > maxAddrLen {
		return fmt.Errorf("address too long: %d bytes", len(addr))
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	if host == "" {
		return fmt.Errorf("empty host in address")
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %s", portStr)
	}

	if ip := net.ParseIP(host); ip != nil {
		if IsPrivateIP(ip) {
			return fmt.Errorf("private IP not allowed: %s", host)
		}
	}

	return nil
}

// SafeDial validates the target address and dials it. For hostnames, it
// resolves DNS and verifies that no resolved IP is private before connecting.
// This prevents SSRF attacks via DNS rebinding.
func SafeDial(addr string) (net.Conn, error) {
	if err := ValidateTarget(addr); err != nil {
		return nil, err
	}

	host, port, _ := net.SplitHostPort(addr)

	// Literal IP: already validated by ValidateTarget, dial directly
	if ip := net.ParseIP(host); ip != nil {
		return net.DialTimeout("tcp4", addr, dialTimeout)
	}

	// Hostname: resolve and validate all IPs before connecting
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}

	for _, ip := range ips {
		if ip.To4() != nil && !IsPrivateIP(ip) {
			return net.DialTimeout("tcp4", net.JoinHostPort(ip.String(), port), dialTimeout)
		}
	}

	return nil, fmt.Errorf("no valid public IPv4 address found for %s", host)
}
