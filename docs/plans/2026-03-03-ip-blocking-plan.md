# IP Blocking Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Block malicious IPs on the remote server using GeoLite2 country database and stamparm/ipsum threat intelligence feed.

**Architecture:** New `IPFilter` in `internal/security/ipfilter.go` loaded at startup. Integrates into `tunnel.Server` as an optional filter checked before rate limiting. Both data sources are file-based and optional (feature activates only when file exists).

**Tech Stack:** `github.com/oschwald/geoip2-golang` for mmdb parsing, standard `bufio`/`net` for ipsum.txt parsing.

---

### Task 1: Add geoip2 dependency

**Step 1:** Install dependency
```bash
cd /workspace && go get github.com/oschwald/geoip2-golang
```

**Step 2:** Verify go.mod updated
```bash
grep geoip2 /workspace/go.mod
```

**Step 3:** Commit
```bash
git add go.mod go.sum && git commit -m "chore: add geoip2-golang dependency for GeoLite2 support"
```

---

### Task 2: Create IPFilter with ipsum.txt support

**Files:**
- Create: `internal/security/ipfilter.go`
- Create: `internal/security/ipfilter_test.go`

**Step 1: Write ipfilter.go**

IPFilter struct with:
- `blockedIPs map[string]struct{}` for ipsum IPs
- `geoDB *geoip2.Reader` for country blocking
- `blockedCountries map[string]struct{}` for ISO codes
- `NewIPFilter() (*IPFilter, error)` that auto-detects files
- `IsBlocked(ip string) bool`
- `Close()`

ipsum.txt parsing: skip `#` comments, split by tab, parse threat level (2nd column), only include level >= 3.

GeoLite2: open `GeoLite2.mmdb` if exists, read `GOPROXY_BLOCKED_COUNTRIES` env var, split by comma, trim, lowercase.

**Step 2: Write tests**

Test ipsum parsing with temp file, test country blocking with mock (since we can't ship mmdb in tests), test IsBlocked logic.

**Step 3: Run tests**
```bash
go test ./internal/security/ -run TestIPFilter -v
```

**Step 4: Commit**

---

### Task 3: Integrate IPFilter into tunnel Server

**Files:**
- Modify: `internal/tunnel/server.go` - add `IPFilter` field, check in `Serve()`
- Modify: `cmd/remote.go` - create IPFilter, pass to Server

**Step 1:** Add `ipFilter *security.IPFilter` to Server struct, add `SetIPFilter()` method.

**Step 2:** In `Serve()`, check `s.ipFilter.IsBlocked(ip)` before rate limiter check.

**Step 3:** In `cmd/remote.go`, create IPFilter and set on server.

**Step 4:** Run all tests
```bash
go test ./... -v
```

**Step 5:** Commit

---

### Task 4: Update TASKS.md and README.md

**Step 1:** Update TASKS.md with milestone checklist (completed).

**Step 2:** Update README.md with IP blocking documentation.

**Step 3:** Commit

