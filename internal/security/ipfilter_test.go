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
	"os"
	"path/filepath"
	"testing"
)

// TestIPFilterNoFiles verifies that when neither ipsum.txt nor GeoLite2.mmdb
// exist, NewIPFilter succeeds and the filter blocks nothing.
func TestIPFilterNoFiles(t *testing.T) {
	// Switch to a temp directory where neither file exists
	tmp := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	f, err := NewIPFilter()
	if err != nil {
		t.Fatalf("NewIPFilter should succeed without files: %v", err)
	}
	defer f.Close()

	if f.IsBlocked("1.2.3.4") {
		t.Fatal("should not block any IP when no files are loaded")
	}
	if f.IsBlocked("10.0.0.1") {
		t.Fatal("should not block any IP when no files are loaded")
	}
}

// TestIPFilterIpsumLoading verifies that IPs with a threat level >= 3 are
// blocked and IPs with level < 3 are not.
func TestIPFilterIpsumLoading(t *testing.T) {
	tmp := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	ipsumContent := "# IPsum threat intelligence\n" +
		"# Generated on 2026-01-01\n" +
		"192.168.1.1\t1\n" +
		"10.0.0.5\t2\n" +
		"203.0.113.50\t3\n" +
		"198.51.100.77\t5\n" +
		"100.64.0.1\t10\n"

	if err := os.WriteFile(filepath.Join(tmp, ipsumFileName), []byte(ipsumContent), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	f, err := NewIPFilter()
	if err != nil {
		t.Fatalf("NewIPFilter failed: %v", err)
	}
	defer f.Close()

	// Level < 3: should NOT be blocked
	if f.IsBlocked("192.168.1.1") {
		t.Error("IP with level 1 should not be blocked")
	}
	if f.IsBlocked("10.0.0.5") {
		t.Error("IP with level 2 should not be blocked")
	}

	// Level >= 3: should be blocked
	if !f.IsBlocked("203.0.113.50") {
		t.Error("IP with level 3 should be blocked")
	}
	if !f.IsBlocked("198.51.100.77") {
		t.Error("IP with level 5 should be blocked")
	}
	if !f.IsBlocked("100.64.0.1") {
		t.Error("IP with level 10 should be blocked")
	}

	// Unknown IP: should not be blocked
	if f.IsBlocked("8.8.8.8") {
		t.Error("unknown IP should not be blocked")
	}
}

// TestIPFilterIpsumComments verifies that comment lines and empty lines
// in ipsum.txt are correctly skipped.
func TestIPFilterIpsumComments(t *testing.T) {
	tmp := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	ipsumContent := "# This is a comment\n" +
		"#Another comment\n" +
		"\n" +
		"   \n" +
		"# 1.2.3.4\t10\n" +
		"5.6.7.8\t5\n"

	if err := os.WriteFile(filepath.Join(tmp, ipsumFileName), []byte(ipsumContent), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	f, err := NewIPFilter()
	if err != nil {
		t.Fatalf("NewIPFilter failed: %v", err)
	}
	defer f.Close()

	// The commented-out IP should not be loaded
	if f.IsBlocked("1.2.3.4") {
		t.Error("commented-out IP should not be blocked")
	}

	// The valid entry should be blocked
	if !f.IsBlocked("5.6.7.8") {
		t.Error("valid IP with level 5 should be blocked")
	}

	// Verify only 1 IP was loaded
	if len(f.blockedIPs) != 1 {
		t.Errorf("expected 1 blocked IP, got %d", len(f.blockedIPs))
	}
}

// TestIPFilterIsBlockedEmpty verifies that a freshly constructed IPFilter
// with no data blocks nothing.
func TestIPFilterIsBlockedEmpty(t *testing.T) {
	f := &IPFilter{
		blockedIPs:       make(map[string]struct{}),
		blockedCountries: make(map[string]struct{}),
	}
	defer f.Close()

	testIPs := []string{
		"1.2.3.4",
		"10.0.0.1",
		"192.168.0.1",
		"::1",
		"2001:db8::1",
		"0.0.0.0",
		"255.255.255.255",
	}

	for _, ip := range testIPs {
		if f.IsBlocked(ip) {
			t.Errorf("empty filter should not block %s", ip)
		}
	}
}

// TestIPFilterGeoLiteSkipped documents that GeoLite2 tests require a
// real .mmdb file and are skipped in unit tests.
func TestIPFilterGeoLiteSkipped(t *testing.T) {
	t.Skip("GeoLite2 tests require a real GeoLite2.mmdb file; skipping in unit tests")
}

// TestIPFilterLoadIpsumFileHelper tests the loadIpsumFile helper directly
// with an explicit path, avoiding the need to change the working directory.
func TestIPFilterLoadIpsumFileHelper(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test_ipsum.txt")

	content := "# header\n" +
		"1.1.1.1\t1\n" +
		"2.2.2.2\t3\n" +
		"3.3.3.3\t7\n" +
		"bad-line-no-tab\n" +
		"4.4.4.4\tnot-a-number\n"

	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	f := &IPFilter{
		blockedIPs:       make(map[string]struct{}),
		blockedCountries: make(map[string]struct{}),
	}

	if err := f.loadIpsumFile(path); err != nil {
		t.Fatalf("loadIpsumFile failed: %v", err)
	}

	// level 1: not blocked
	if _, ok := f.blockedIPs["1.1.1.1"]; ok {
		t.Error("1.1.1.1 (level 1) should not be in blockedIPs")
	}

	// level 3: blocked
	if _, ok := f.blockedIPs["2.2.2.2"]; !ok {
		t.Error("2.2.2.2 (level 3) should be in blockedIPs")
	}

	// level 7: blocked
	if _, ok := f.blockedIPs["3.3.3.3"]; !ok {
		t.Error("3.3.3.3 (level 7) should be in blockedIPs")
	}

	// malformed lines should be silently skipped
	if len(f.blockedIPs) != 2 {
		t.Errorf("expected 2 blocked IPs, got %d", len(f.blockedIPs))
	}
}

// TestIPFilterLoadIpsumFileNotExist verifies that loadIpsumFile gracefully
// handles a missing file (returns nil, not an error).
func TestIPFilterLoadIpsumFileNotExist(t *testing.T) {
	f := &IPFilter{
		blockedIPs:       make(map[string]struct{}),
		blockedCountries: make(map[string]struct{}),
	}

	err := f.loadIpsumFile("/nonexistent/path/ipsum.txt")
	if err != nil {
		t.Fatalf("loadIpsumFile should return nil for missing file, got: %v", err)
	}

	if len(f.blockedIPs) != 0 {
		t.Error("no IPs should be loaded from a missing file")
	}
}

// TestIPFilterCloseNilGeoDB verifies that Close does not panic when
// geoDB is nil.
func TestIPFilterCloseNilGeoDB(t *testing.T) {
	f := &IPFilter{
		blockedIPs:       make(map[string]struct{}),
		blockedCountries: make(map[string]struct{}),
	}

	// Should not panic
	f.Close()
}
