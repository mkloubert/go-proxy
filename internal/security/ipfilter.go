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
	"bufio"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

const (
	ipsumFileName    = "ipsum.txt"
	geoLiteFileName  = "GeoLite2.mmdb"
	ipsumMinLevel    = 3
	blockedCountriesEnv = "GOPROXY_BLOCKED_COUNTRIES"
)

// IPFilter blocks connections from known-malicious IPs (via ipsum.txt)
// and from specific countries (via GeoLite2 + GOPROXY_BLOCKED_COUNTRIES).
// A zero-value IPFilter blocks nothing.
type IPFilter struct {
	blockedIPs       map[string]struct{}
	geoDB            *geoip2.Reader
	blockedCountries map[string]struct{}
}

// NewIPFilter creates an IPFilter by loading optional ipsum.txt and
// GeoLite2.mmdb files from the current working directory. If neither
// file exists, the returned filter blocks nothing.
func NewIPFilter() (*IPFilter, error) {
	f := &IPFilter{
		blockedIPs:       make(map[string]struct{}),
		blockedCountries: make(map[string]struct{}),
	}

	if err := f.loadIpsumFile(ipsumFileName); err != nil {
		return nil, err
	}

	if err := f.loadGeoDB(geoLiteFileName); err != nil {
		return nil, err
	}

	return f, nil
}

// loadIpsumFile reads an ipsum-formatted threat intelligence file.
// Lines starting with '#' are comments. Data lines have the format
// "IP\tcount"; only IPs with count >= ipsumMinLevel are loaded.
func (f *IPFilter) loadIpsumFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}

		ip := strings.TrimSpace(parts[0])
		countStr := strings.TrimSpace(parts[1])

		count, err := strconv.Atoi(countStr)
		if err != nil {
			continue
		}

		if count >= ipsumMinLevel {
			f.blockedIPs[ip] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	slog.Info("ipfilter: loaded IPs from ipsum", "count", len(f.blockedIPs), "file", path, "minLevel", ipsumMinLevel)
	return nil
}

// loadGeoDB opens a MaxMind GeoLite2 database and reads blocked
// country codes from the GOPROXY_BLOCKED_COUNTRIES environment variable.
func (f *IPFilter) loadGeoDB(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	db, err := geoip2.Open(path)
	if err != nil {
		return err
	}
	f.geoDB = db

	envVal := os.Getenv(blockedCountriesEnv)
	if envVal == "" {
		slog.Info("ipfilter: GeoLite2 loaded but no countries configured", "envVar", blockedCountriesEnv)
		return nil
	}

	for _, code := range strings.Split(envVal, ",") {
		code = strings.ToLower(strings.TrimSpace(code))
		if code != "" {
			f.blockedCountries[code] = struct{}{}
		}
	}

	codes := make([]string, 0, len(f.blockedCountries))
	for c := range f.blockedCountries {
		codes = append(codes, c)
	}
	slog.Info("ipfilter: blocking countries", "countries", codes)

	return nil
}

// IsBlocked returns true if the given IP string should be rejected.
// An IP is blocked if it appears in the ipsum list or if its GeoIP
// country is in the configured blocked-countries set.
func (f *IPFilter) IsBlocked(ip string) bool {
	if _, ok := f.blockedIPs[ip]; ok {
		return true
	}

	if f.geoDB != nil && len(f.blockedCountries) > 0 {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return false
		}

		record, err := f.geoDB.Country(parsed)
		if err != nil {
			return false
		}

		code := strings.ToLower(record.Country.IsoCode)
		if _, ok := f.blockedCountries[code]; ok {
			return true
		}
	}

	return false
}

// Close releases resources held by the IPFilter, in particular the
// GeoLite2 database handle.
func (f *IPFilter) Close() {
	if f.geoDB != nil {
		f.geoDB.Close()
	}
}
